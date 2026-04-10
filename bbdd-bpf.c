// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <assert.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <json-c/json_object.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/param.h>

#include "bbdd.h"
#include "bbdd-nl.h"
#include "bbdd-prog.h"
#include "bbdd-util.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "bbdd-prog.skel.h"
#pragma GCC diagnostic pop

struct bbdd_bpf_attachment {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
};

/* Interface between bbdd_bpf_rb_recv() and bbdd_bpf_rb_handle(). */
struct bbdd_bpf_rb_context {
	struct bbdd_bpf *bpf;
	struct ring_buffer *rb;
	struct bbdd_nl *nl;
	struct bbdd_sess_dir *sdir;
	char **error;
};

struct bbdd_bpf {
	/* Some of the conf information is not strictly necessary to keep around
	 * or duplicated in the attachments, but it's easier to keep it all. */
	struct bbdd_bpf_global_config conf;

	struct bbdd_prog *skel;
	struct bbdd_bpf_attachment *rx;
	struct bbdd_bpf_attachment *tx;
	struct bbdd_bpf_rb_context *rb_ctx;
};

/* Per-session data. */
struct bbdd_bpf_session {
	uint32_t gen_id;
	int sock_fd;
};

static int bbdd_bpf_print(enum libbpf_print_level level,
			  const char *fmt, va_list args)
{
	if ((int)level <= bbdd_env.verbosity)
		vfprintf(stderr, fmt, args);
	return 0;
}

static struct bbdd_bfd_control_packet
bbdd_bpf_make_packet(const struct bbdd_d_session_data *state,
		     uint32_t your_disc, uint8_t flags)
{
	enum { v1 = 1 };
	return (struct bbdd_bfd_control_packet) {
		.version_diag = (v1 << 5) | (uint8_t) state->state.diag,
		.state_bits = (uint8_t) (state->state.state << 6 | flags),
		.detection_multiplier = state->detect_mult,
		.length = sizeof(struct bbdd_bfd_control_packet),
		.my_disc = htonl(state->discr),
		.your_disc = htonl(your_disc),
		.desired_tx = htonl(state->min_tx_us),
		.required_rx = htonl(state->min_rx_us),
		.required_echo_rx = 0,
	};
}

static uint32_t bbdd_bpf_cksum_acc(uint32_t sum, const void *buf, size_t len)
{
	const uint16_t *p = buf;

	while (len >= 2) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	return sum;
}

static uint16_t bbdd_bpf_cksum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~(uint16_t)sum;
}

static uint16_t bbdd_bpf_inet_cksum(const void *buf, size_t len)
{
	return bbdd_bpf_cksum_fold(bbdd_bpf_cksum_acc(0, buf, len));
}

/* udp_len is in host byte order; udp points to UDP header followed by data */
static uint16_t bbdd_bpf_udp6_cksum(const struct ip6_hdr *ip6,
				    const void *udp, uint16_t udp_len)
{
	struct {
		struct in6_addr src;
		struct in6_addr dst;
		__be32 len;
		uint8_t zeros[3];
		uint8_t nxt;
	} pseudo = {
		.src = ip6->ip6_src,
		.dst = ip6->ip6_dst,
		.len = htonl(udp_len),
		.nxt = IPPROTO_UDP,
	};
	uint32_t sum = 0;

	sum = bbdd_bpf_cksum_acc(sum, &pseudo, sizeof(pseudo));
	sum = bbdd_bpf_cksum_acc(sum, udp, udp_len);
	return bbdd_bpf_cksum_fold(sum);
}

static int bbdd_bpf_session_inject_pkt(const struct bbdd_d_session *dsess,
				       struct bbdd_bpf_session *bsess,
				       uint32_t tx_ifindex,
				       uint8_t bfd_flags, char **error)
{
	struct bbdd_bfd_control_packet bfd;
	union {
		struct sockaddr    sa;
		struct sockaddr_ll sll;
	} dst_sa = {};
	uint8_t ttl;
	ssize_t rc;

	/* RFC: When a BFD session is directly connected across a single link
	 * (physical, or a secure tunnel such as IPsec), the TTL or Hop Count
	 * MUST be set to the maximum on transmit.
	 *
	 * For multi-hop sessions the RFC recommends auth. We can just set the
	 * TTL to maximum always.
	 */
	ttl = 255;

	bfd = bbdd_bpf_make_packet(&dsess->local, dsess->remote.discr,
				   bfd_flags);

	dst_sa.sll.sll_family  = AF_PACKET;
	dst_sa.sll.sll_ifindex = (int)tx_ifindex;
	dst_sa.sll.sll_halen   = ETH_ALEN;
	memset(dst_sa.sll.sll_addr, 0xff, ETH_ALEN);

	if (dsess->dst.sa.sa_family == AF_INET) {
		struct {
			struct iphdr ip;
			struct udphdr udp;
			struct bbdd_bfd_control_packet bfd;
		} pkt = {};
		uint16_t udp_len = sizeof(pkt.udp) + sizeof(pkt.bfd);

		pkt.bfd        = bfd;
		pkt.udp.source = dsess->src.sin.sin_port;
		pkt.udp.dest   = dsess->dst.sin.sin_port;
		pkt.udp.len    = htons(udp_len);
		pkt.udp.check  = 0; /* optional for IPv4 */

		pkt.ip.version  = 4;
		pkt.ip.ihl      = 5;
		pkt.ip.tot_len  = htons(sizeof(pkt));
		pkt.ip.ttl      = ttl;
		pkt.ip.protocol = IPPROTO_UDP;
		pkt.ip.saddr    = dsess->src.sin.sin_addr.s_addr;
		pkt.ip.daddr    = dsess->dst.sin.sin_addr.s_addr;
		pkt.ip.check    = bbdd_bpf_inet_cksum(&pkt.ip, sizeof(pkt.ip));

		dst_sa.sll.sll_protocol = htons(ETH_P_IP);

		rc = sendto(bsess->sock_fd, &pkt, sizeof(pkt), 0,
			    &dst_sa.sa, sizeof(dst_sa.sll));
	} else {
		struct {
			struct ip6_hdr ip6;
			struct udphdr udp;
			struct bbdd_bfd_control_packet bfd;
		} pkt = {};
		uint16_t udp_len = sizeof(pkt.udp) + sizeof(pkt.bfd);

		pkt.bfd        = bfd;
		pkt.udp.source = dsess->src.sin6.sin6_port;
		pkt.udp.dest   = dsess->dst.sin6.sin6_port;
		pkt.udp.len    = htons(udp_len);

		pkt.ip6.ip6_vfc  = 0x60; /* version 6 */
		pkt.ip6.ip6_plen = htons(udp_len);
		pkt.ip6.ip6_nxt  = IPPROTO_UDP;
		pkt.ip6.ip6_hlim = ttl;
		pkt.ip6.ip6_src  = dsess->src.sin6.sin6_addr;
		pkt.ip6.ip6_dst  = dsess->dst.sin6.sin6_addr;
		pkt.udp.check    = bbdd_bpf_udp6_cksum(&pkt.ip6, &pkt.udp,
						       udp_len);

		dst_sa.sll.sll_protocol = htons(ETH_P_IPV6);
		rc = sendto(bsess->sock_fd, &pkt, sizeof(pkt), 0,
			    &dst_sa.sa, sizeof(dst_sa.sll));
	}

	if (rc < 0) {
		bbdd_util_fmterr(error, "sendto(bfd_tx): %d %m", errno);
		return -1;
	}
	return 0;
}

static int
bbdd_bpf_parse_packet(const struct bbdd_bfd_control_packet *packet,
		      struct bbdd_d_session_data *data,
		      bool *poll)
{
	uint8_t bits = bbdd_bpf_control_packet_bits(packet);
	uint32_t remote_discr = ntohl(packet->my_disc);
	uint32_t local_discr = ntohl(packet->your_disc);
	enum bfd_state_value state = bbdd_bpf_control_packet_state(packet);

	// xxx the messages here should either go to char **error, or more
	// likely bump counters.

	/* Note: Version and length are validated in BPF. */

	if (packet->required_echo_rx != 0) {
		fprintf(stderr, "echo not supported. Flags=%#x\n", bits);
		return -1;
	}

	if (bits & BBDD_BFD_PACKET_BIT_AUTH) {
		fprintf(stderr, "auth not supported. Flags=%#x\n", bits);
		return -1;
	}

	if (bits & BBDD_BFD_PACKET_BIT_DEMAND) {
		fprintf(stderr, "demand not supported. Flags=%#x\n", bits);
		return -1;
	}

	if (bits & BBDD_BFD_PACKET_BIT_MULTI) {
		fprintf(stderr, "multipoint not supported. Flags=%#x\n", bits);
		return -1;
	}

	if (packet->detection_multiplier == 0) {
		fprintf(stderr, "Invalid detection multiplier of 0\n");
		return -1;
	}

	if (remote_discr == 0) {
		fprintf(stderr, "Invalid my_discr of 0\n");
		return -1;
	}

	if (local_discr == 0 &&
	    state != STATE_ADMINDOWN && state != STATE_DOWN) {
		fprintf(stderr, "Invalid your_disc of 0 when state not downish\n");
		return -1;
	}

	if (remote_discr != 0)
		data->discr = remote_discr;
	data->detect_mult = packet->detection_multiplier;
	data->min_rx_us = ntohl(packet->required_rx);
	data->min_tx_us = ntohl(packet->desired_tx);
	data->detect_mult = packet->detection_multiplier;
	data->state.state = state;
	data->state.diag = bbdd_bfd_control_packet_diag(packet);

	*poll = bits & BBDD_BFD_PACKET_BIT_POLL;

	return 0;
}

static int bbdd_bpf_session_conf_update(struct bbdd_bpf *bpf,
					const struct bbdd_d_session *dsess,
					struct bbdd_bpf_session *bsess,
					uint32_t ifindex,
					uint32_t tbid,
					uint32_t flags,
					uint32_t min_interval_us,
					uint32_t max_interval_us,
					char **error)
{
	const struct bbdd_sockaddr *src = &dsess->src;
	const struct bbdd_sockaddr *dst = &dsess->dst;
	int af = src->sa.sa_family ?: dst->sa.sa_family;
	uint32_t discr = dsess->local.discr;
	struct bbdd_prog_session_config config = {
		.fib_lookup = {
			.family = (uint8_t) af,
			.l4_protocol = IPPROTO_UDP,
			.sport = src->sin46.port,
			.dport = dst->sin46.port,
			.ifindex = ifindex,
			.tbid = tbid,
			.mark = bsess->gen_id,
		},
		.bpf_fib_lookup_flags = flags,
		.min_interval_us = min_interval_us,
		.max_interval_us = max_interval_us,
		.gen_id = bsess->gen_id,
		.admin_down = dsess->local.state.state == STATE_ADMINDOWN,
		.ttl = dsess->ttl,
		.rx_expect = bbdd_bpf_make_packet(&dsess->remote,
						  dsess->local.discr, 0),
	};
	int err;

	if (af != dst->sa.sa_family) {
		bbdd_util_fmterr(error, "Mismatch in families of source and destination addresses");
		return -1;
	}

	switch (af) {
	case AF_INET:
		config.fib_lookup.ipv4_src = src->sin.sin_addr.s_addr;
		config.fib_lookup.ipv4_dst = dst->sin.sin_addr.s_addr;
		break;
	case AF_INET6:
		memcpy(config.fib_lookup.ipv6_src, &src->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_src));
		memcpy(config.fib_lookup.ipv6_dst, &dst->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_dst));
		break;
	default:
		bbdd_util_fmterr(error, "Unsupported session address family %d",
				 af);
		return -1;
	}

	err = bpf_map__update_elem(bpf->skel->maps.bbdd_prog_session_config_hash,
				   &discr, sizeof(discr),
				   &config, sizeof(config),
				   BPF_ANY);
	if (err) {
		bbdd_util_fmterr(error, "Failed to insert / update BPF session config: %s",
				 strerror(-err));
		return -1;
	}

	return 0;
}

static int bbdd_bpf_session_conf_add(struct bbdd_bpf *bpf,
				     const struct bbdd_d_session *dsess,
				     struct bbdd_bpf_session *bsess,
				     uint32_t ifindex,
				     uint32_t tbid,
				     uint32_t flags,
				     uint32_t min_interval_us,
				     uint32_t max_interval_us,
				     char **error)
{
	struct bbdd_prog_session_data data = {};
	uint32_t discr = dsess->local.discr;
	int err;

	err = bbdd_bpf_session_conf_update(bpf, dsess, bsess, ifindex,
					   tbid, flags, min_interval_us,
					   max_interval_us, error);
	if (err)
		return err;

	err = bpf_map__update_elem(bpf->skel->maps.bbdd_prog_session_data_hash,
				   &discr, sizeof(discr),
				   &data, sizeof(data),
				   BPF_ANY);
	if (err) {
		bbdd_util_fmterr(error, "Failed to insert session data: %s",
				 strerror(-err));
		goto delete;
	}

	return 0;

delete:
	bpf_map__delete_elem(bpf->skel->maps.bbdd_prog_session_config_hash,
			     &discr, sizeof(discr), 0);
	return err;
}

static void bbdd_bpf_session_conf_delete(struct bbdd_bpf *bpf, uint32_t discr)
{
	int err;

	err = bpf_map__delete_elem(bpf->skel->maps.bbdd_prog_session_config_hash,
				   &discr, sizeof(discr), 0);
	if (err != 0)
		fprintf(stderr, "Couldn't delete session %u from session_config_hash\n",
			discr);

	err = bpf_map__delete_elem(bpf->skel->maps.bbdd_prog_session_data_hash,
				   &discr, sizeof(discr), 0);
	if (err != 0)
		fprintf(stderr, "Couldn't delete session %u from session_data_hash\n",
			discr);
}

static int
bbdd_bpf_addr_to_sockaddr(uint16_t ethtype,
			  const struct bbdd_bpf_addr *bfd_addr,
			  struct bbdd_sockaddr *addr,
			  const char *context,
			  char **error)
{
	switch (ethtype) {
	case ETH_P_IP:
		addr->sa.sa_family = AF_INET;
		memcpy(&addr->sin.sin_addr, bfd_addr->addr,
		       sizeof(addr->sin.sin_addr));
		addr->len = sizeof(addr->sin);
		return 0;
	case ETH_P_IPV6:
		addr->sa.sa_family = AF_INET6;
		memcpy(&addr->sin6.sin6_addr, bfd_addr->addr,
		       sizeof(addr->sin6.sin6_addr));
		addr->len = sizeof(addr->sin6);
		return 0;
	}

	bbdd_util_fmterr(error, "%s: invalid ethtype %#x", context, ethtype);
	return -EPROTO;
}

static int
bbdd_bpf_rb_handle_no_neighbor(const struct bbdd_bpf_rb_elem_tx_no_neighbor *elem,
			       struct bbdd_nl *nl, char **error)
{
	struct bbdd_sockaddr addr = {};
	int err;

	err = bbdd_bpf_addr_to_sockaddr(elem->ethtype, &elem->addr, &addr,
					"BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR",
					error);
	if (err)
		return err;

	return bbdd_nl_refresh_neigh(nl, (uint32_t)elem->ifindex, &addr, error);
}

/* Return number of found sessions, or < 0 on error. The last matched session,
 * if any, is returned through ret_discr. */
static int
bbdd_bpf_rb_discr0_find_session(uint32_t *ret_discr,
				struct bbdd_sess_dir *sdir,
				uint32_t ifindex,
				bool multihop,
				const struct bbdd_sockaddr *pk_src,
				const struct bbdd_sockaddr *pk_dst,
				char **error)
{
	int nmatch = 0;
	int err;

	for (struct bbdd_d_session *dsess = bbdd_sess_iter_start(sdir);
	     dsess != NULL; dsess = bbdd_sess_iter_next(dsess)) {
		const struct bbdd_sockaddr *ss_src = &dsess->src;
		const struct bbdd_sockaddr *ss_dst = &dsess->dst;

		if (multihop != dsess->flags.multihop)
			continue;

		if (dsess->ifindex != 0 && dsess->ifindex != ifindex)
			continue;

		/* This is incoming packet aimed at us, so we need to match
		 * packet DST vs. session SRC and vice versa. */

		if (ss_src->sa.sa_family == 0)
			/* Session doesn't have set source address. */
			goto src;
		if (ss_src->sa.sa_family != pk_dst->sa.sa_family)
			continue;

		err = bbdd_sockaddr_eq(ss_src, pk_dst, error);
		if (err < 0)
			return err;
		if (err == false)
			/* ss_src != pk_dst. */
			continue;

	src:
		if (ss_dst->sa.sa_family == 0)
			/* Session doesn't have set destination address. Weird,
			 * but we are not validating here, so eat it. */
			goto match;
		if (ss_dst->sa.sa_family != pk_src->sa.sa_family)
			continue;

		err = bbdd_sockaddr_eq(ss_dst, pk_src, error);
		if (err < 0)
			return err;
		if (err == false)
			/* ss_dst != pk_src. */
			continue;

	match:
		nmatch++;
		*ret_discr = dsess->local.discr;
	}

	return nmatch;
}

static void
bbdd_bpf_handle_packet(struct bbdd_bpf *bpf,
		       struct bbdd_sess_dir *sdir,
		       const struct bbdd_bfd_control_packet *packet,
		       uint8_t ttl)
{
	uint32_t local_discr = ntohl(packet->your_disc);
	uint32_t remote_discr = ntohl(packet->my_disc);
	struct bbdd_d_session_data old_local;
	struct bbdd_d_session_data old_remote;
	struct bbdd_bpf_session *bsess;
	struct bbdd_d_session *dsess;
	char *error;
	bool poll;
	int err;

	fprintf(stderr, "Process packet: local %u remote %u\n",
		local_discr, remote_discr);

	/* Errors here are problematic, but not worth killing the daemon
	 * over. Just eat them. */

	dsess = bbdd_sess_dir_get_session(sdir, local_discr);
	if (dsess == NULL) {
		/* I think this can come up when BPF found a session and emit an
		 * event, but before we got to process it, the session gets
		 * deleted. So don't even print anything. */
		return;
	}

	// xxx this accesses dsess->bpf, which it shouldn't. The fact that -d.c
	// keeps the pointer in dsess is an implementation detail.
	bsess = dsess->bpf;

	/* For admin down sessions where your_disc is given, we don't even get
	 * to see these packets, because BPF shoots them down. But when
	 * your_disc == 0, the packets are processed here, and we need to shoot
	 * them down ourselves.
	 */
	if (dsess->local.state.state == STATE_ADMINDOWN)
		// xxx bump rx_admin_down
		return;

	/* RFC: [For single-hop sessions] TTL or Hop Count MUST be set to the
	 * maximum on transmit, and checked to be equal to the maximum value on
	 * reception.
	 *
	 * We always set TTL to 255, and let the user configure per-session what
	 * value of incoming TTL they tolerate. The RFC doesn't directly say
	 * that non-matching packets must be dropped, but what else.
	 */
	if (dsess->ttl > ttl)
		// xxx bump rx_ttl_low
		return;

	old_local = dsess->local;
	old_remote = dsess->remote;

	err = bbdd_bpf_parse_packet(packet, &dsess->remote, &poll);
	if (err)
		return;

	if (dsess->remote.state.state == STATE_ADMINDOWN) {
		if (dsess->local.state.state != STATE_DOWN) {
			dsess->local.state.state = STATE_DOWN;
			dsess->local.state.diag = DIAG_DOWN;
			// xxx should this reset timers to slow? And the same
			// below.
			// xxx should we at some point reset the remote
			// discriminator? Otherwise we'll keep referring to
			// a your_disc that may be long gone.
		}
	} else {
		switch (dsess->local.state.state) {
		case STATE_ADMINDOWN:
			break;

		case STATE_DOWN:
			if (dsess->remote.state.state == STATE_DOWN)
				dsess->local.state.state = STATE_INIT;
			else if (dsess->remote.state.state == STATE_INIT)
				dsess->local.state.state = STATE_UP;
			break;

		case STATE_INIT:
			if (dsess->remote.state.state == STATE_INIT ||
			    dsess->remote.state.state == STATE_UP)
				dsess->local.state.state = STATE_UP;
			break;

		case STATE_UP:
			if (dsess->remote.state.state == STATE_DOWN) {
				dsess->local.state.state = STATE_DOWN;
				dsess->local.state.diag = DIAG_DOWN;
			}
			break;
		}
	}

	if (memcmp(&old_local, &dsess->local, sizeof(old_local)) == 0 &&
	    memcmp(&old_remote, &dsess->remote, sizeof(old_remote)) == 0)
		goto poll_respond;


	{
		struct json_object *obj;
		bool printed = false;

		obj = bbdd_d_session_json(dsess);
		if (obj != NULL) {
			const char *str;

			str = json_object_to_json_string(obj);
			if (str != NULL) {
				fprintf(stderr, "state change %s\n", str);
				printed = true;
			}

			json_object_put(obj);
		}

		if (!printed)
			fprintf(stderr, "state change, but formatting error\n");
	}

	err = bbdd_bpf_session_update(bpf, dsess, bsess, &error);
	if (err != 0)
		bbdd_util_printerr(err, &error, "discr_resolve: session %u: Failed to update session",
				   dsess->local.discr);

poll_respond:
	if (poll) {
		err = bbdd_bpf_session_inject_pkt(dsess, bsess,
						  bpf->conf.veth_tx_ifindex,
						  BBDD_BFD_PACKET_BIT_FINAL,
						  &error);
		if (err != 0)
			bbdd_util_printerr(err, &error, "Failed to respond to a poll packet");
	}
}

static void
bbdd_bpf_rb_handle_discr_0(const struct bbdd_bpf_rb_elem_rx_discr_0 *elem,
			   struct bbdd_bpf *bpf, struct bbdd_sess_dir *sdir)
{
	struct bbdd_sockaddr saddr;
	struct bbdd_sockaddr daddr;
	uint32_t discr;
	int err;
	unsigned int nmatch;
	char *error;

	err = bbdd_bpf_addr_to_sockaddr(elem->ethtype, &elem->saddr, &saddr,
					"BBDD_BPF_RB_ELEM_RX_DISCR_0",
					&error);
	if (err != 0)
		goto error;

	err = bbdd_bpf_addr_to_sockaddr(elem->ethtype, &elem->daddr, &daddr,
					"BBDD_BPF_RB_ELEM_RX_DISCR_0",
					&error);
	if (err != 0)
		goto error;

	err = bbdd_bpf_rb_discr0_find_session(&discr, sdir,
					      elem->ifindex, elem->multihop,
					      &saddr, &daddr, &error);
	if (err < 0)
		goto error;

	nmatch = (unsigned int) err;

	/* xxx I think there should be counters for the various scenarios:
	 * your_disc given, but not found, your_disc given, but no matches
	 * found, or given, but many matches found. Maybe emit a monitor event
	 * (when that exists). For now just print a message. */
	if (nmatch != 1) {
		char src_str[INET6_ADDRSTRLEN] = {};
		char dst_str[INET6_ADDRSTRLEN] = {};

		err = bbdd_sockaddr_ntop(&saddr, src_str, sizeof(src_str), &error);
		if (err != 0)
			goto error;

		err = bbdd_sockaddr_ntop(&daddr, dst_str, sizeof(dst_str), &error);
		if (err != 0)
			goto error;

		fprintf(stderr, "RX: session lookup for iif %d src %s dst %s ttl %d multihop %d: expected one match, got %u\n",
			elem->ifindex, src_str, dst_str, elem->ttl, elem->multihop, nmatch);
		return;
	}

	fprintf(stderr, "Matched session with discrimator %u\n", discr);

	return bbdd_bpf_handle_packet(bpf, sdir, &elem->packet, elem->ttl);

error:
	bbdd_util_printerr(err, &error, "bbdd_bpf_rb_handle_discr_0");
}

static void
bbdd_bpf_rb_handle_unx_packet(const struct bbdd_bpf_rb_elem_rx_unx_packet *elem,
			      struct bbdd_bpf *bpf,
			      struct bbdd_sess_dir *sdir)
{
	fprintf(stderr, "Unexpected packet\n");
	return bbdd_bpf_handle_packet(bpf, sdir, &elem->packet, elem->ttl);
}

static int bbdd_bpf_rb_handle(void *ctx, void *data, size_t)
{
	struct bbdd_bpf_rb_context *rb_ctx = ctx;
	const struct bbdd_bpf_rb_elem_head *head = data;

	switch (head->type) {
	case BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR:
		return bbdd_bpf_rb_handle_no_neighbor(data, rb_ctx->nl,
						      rb_ctx->error);
	case BBDD_BPF_RB_ELEM_RX_DISCR_0:
		bbdd_bpf_rb_handle_discr_0(data, rb_ctx->bpf, rb_ctx->sdir);
		break;
	case BBDD_BPF_RB_ELEM_RX_UNX_PACKET:
		bbdd_bpf_rb_handle_unx_packet(data, rb_ctx->bpf, rb_ctx->sdir);
		break;
	case BBDD_BPF_RB_ELEM_RX_TIMEOUT:
		fprintf(stderr, "unhandled RB event type %d\n", head->type);
		break;
	}
	return 0;
}

static int bbdd_bpf_rb_recv(struct bbdd_poll_ctx *, void *data, char **error)
{
	struct bbdd_bpf_rb_context *rb_ctx = data;
	int ret;

	rb_ctx->error = error;
	ret = ring_buffer__consume(rb_ctx->rb);
	rb_ctx->error = NULL;
	if (ret < 0)
		return -1;

	return 0;
}

static struct bbdd_bpf_rb_context *
bbdd_bpf_rb_init(struct bbdd_prog *skel, struct bbdd_poll_ctx *pctx,
		 struct bbdd_nl *nl, struct bbdd_sess_dir *sdir,
		 char **error)
{
	struct bbdd_bpf_rb_context *rb_ctx;
	struct ring_buffer *rb;
	int rb_fd;
	int err;

	rb_ctx = malloc(sizeof(*rb_ctx));
	if (rb_ctx == NULL) {
		bbdd_util_fmterr(error, "bbdd_bpf_rb_setup: %m");
		return NULL;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.bbdd_bpf_rb),
			      bbdd_bpf_rb_handle, rb_ctx, NULL);
	if (!rb) {
		bbdd_util_fmterr(error, "ring_buffer__new: %m");
		goto free_ctx;
	}

	rb_fd = ring_buffer__epoll_fd(rb);
	err = bbdd_poll_push_fd(pctx, rb_fd, POLLIN, bbdd_bpf_rb_recv, rb_ctx,
				error);
	if (err != 0)
		goto free_ring_buffer;

	*rb_ctx = (struct bbdd_bpf_rb_context) {
		.rb = rb,
		.nl = nl,
		.sdir = sdir,
	};
	return rb_ctx;

free_ring_buffer:
	ring_buffer__free(rb);
free_ctx:
	free(rb_ctx);
	return NULL;
}

static void bbdd_bpf_rb_fini(struct bbdd_bpf_rb_context *rb_ctx)
{
	ring_buffer__free(rb_ctx->rb);
	free(rb_ctx);
}

static int bbdd_bpf_attach_sock(struct bpf_program *prog, int sock_fd,
				char **error)
{
	int prog_fd = bpf_program__fd(prog);

	if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
		       &prog_fd, sizeof(prog_fd)) < 0) {
		bbdd_util_fmterr(error, "SO_ATTACH_BPF: %m");
		return -1;
	}
	return 0;
}

static void bbdd_bpf_detach_sock(int sock_fd)
{
	setsockopt(sock_fd, SOL_SOCKET, SO_DETACH_BPF, NULL, 0);
}

static struct bbdd_bpf_attachment *
bbdd_bpf_attach(struct bpf_program *prog, uint32_t ifindex,
		enum bpf_tc_attach_point attach_point,
		char **error)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = (int)ifindex,
		.attach_point = attach_point,
	};
	struct bbdd_bpf_attachment *attachment;
	struct bpf_tc_opts opts;
	int err;

	attachment = malloc(sizeof(*attachment));
	if (!attachment) {
		bbdd_util_fmterr(error, "bbdd_bpf_attach: %m");
		return NULL;
	}

	err = bpf_tc_hook_create(&hook);
	if (err) {
		bbdd_util_fmterr(error, "bpf_tc_hook_create(ifindex=%u): %s",
				 ifindex, strerror(-err));
		goto free;
	}

	opts = (struct bpf_tc_opts) {
		.sz = sizeof(opts),
		.prog_fd = bpf_program__fd(prog),
		.handle = 1,
		.priority = 1,
	};

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		bbdd_util_fmterr(error, "bpf_tc_attach(ifindex=%u): %s",
				 ifindex, strerror(-err));
		goto hook_destroy;
	}

	*attachment = (struct bbdd_bpf_attachment) {
		.hook = hook,
		.opts = opts,
	};
	return attachment;

hook_destroy:
	bpf_tc_hook_destroy(&hook);
free:
	free(attachment);
	return NULL;
}

static void bbdd_bpf_detach(struct bbdd_bpf_attachment *attachment)
{
	bpf_tc_detach(&attachment->hook, &attachment->opts);
	free(attachment);
}

struct bbdd_bpf *bbdd_bpf_create(struct bbdd_poll_ctx *pctx,
				 struct bbdd_nl *nl,
				 struct bbdd_bpf_global_config *conf,
				 struct bbdd_sess_dir *sdir,
				 char **error)
{
	struct bbdd_bpf *bpf;
	int err;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL) {
		bbdd_util_fmterr(error, "calloc: %m");
		return NULL;
	}

	bpf->conf = *conf;

	libbpf_set_print(bbdd_bpf_print);

	bpf->skel = bbdd_prog__open_and_load();
	if (!bpf->skel) {
		bbdd_util_fmterr(error, "bbdd_prog__open_and_load: %m");
		goto free_bpf;
	}

	bpf->rb_ctx = bbdd_bpf_rb_init(bpf->skel, pctx, nl, sdir, error);
	if (bpf->rb_ctx == NULL)
		goto destroy_prog;
	bpf->rb_ctx->bpf = bpf;

	bpf->skel->bss->bbdd_veth_tx_ifindex = (int)conf->veth_tx_ifindex;

	/* Attach programs as the last step when everything else is
	 * prepared. */

	bpf->rx = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_rx,
				  conf->veth_rx_ifindex,
				  BPF_TC_INGRESS, error);
	if (bpf->rx == NULL)
		goto free_rb_ctx;

	bpf->tx = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_tx,
				  conf->veth_tx_ifindex,
				  BPF_TC_EGRESS, error);
	if (bpf->tx == NULL)
		goto detach_rx;

	err = bbdd_bpf_attach_sock(bpf->skel->progs.bbdd_recv,
				   conf->ipv4_fd, error);
	if (err != 0)
		goto detach_tx;

	err = bbdd_bpf_attach_sock(bpf->skel->progs.bbdd_recv,
				   conf->ipv6_fd, error);
	if (err != 0)
		goto detach_ipv4;

	return bpf;

detach_ipv4:
	bbdd_bpf_detach_sock(conf->ipv4_fd);
detach_tx:
	bbdd_bpf_detach(bpf->tx);
detach_rx:
	bbdd_bpf_detach(bpf->rx);
free_rb_ctx:
	bbdd_bpf_rb_fini(bpf->rb_ctx);
destroy_prog:
	bbdd_prog__destroy(bpf->skel);
free_bpf:
	free(bpf);
	return NULL;
}

void bbdd_bpf_destroy(struct bbdd_bpf *bpf)
{
	bbdd_bpf_detach_sock(bpf->conf.ipv6_fd);
	bbdd_bpf_detach_sock(bpf->conf.ipv4_fd);
	bbdd_bpf_detach(bpf->tx);
	bbdd_bpf_detach(bpf->rx);
	bbdd_bpf_rb_fini(bpf->rb_ctx);
	bbdd_prog__destroy(bpf->skel);
	free(bpf);
}

static void bbdd_bpf_stat_fmterr(char **error)
{
	bbdd_util_fmterr(error, "Failed to format stats to JSON: %m");
}

static int bbdd_bpf_add_stat(struct json_object *obj,
			     const char *name, uint64_t value,
			     char **error)
{
	int rc;
	rc = json_object_object_add(obj, name, json_object_new_uint64(value));
	if (rc)
		bbdd_bpf_stat_fmterr(error);
	return rc;
}

struct json_object *bbdd_bpf_global_diag_stats_json(struct bbdd_bpf *bpf,
						    char **error)
{
	struct bbdd_prog_global_diag_stats *stats;
	struct json_object *obj;

	stats = &bpf->skel->bss->bbdd_prog_global_diag_stats;

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)						\
	if (bbdd_bpf_add_stat(obj, #NAME, stats->NAME, error))	\
		goto err;

	BBDD_GLOBAL_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_bpf_session_diag_stats_json(struct bbdd_bpf *bpf,
						     uint32_t id,
						     char **error)
{
	struct bbdd_prog_session_data data;
	struct json_object *obj;
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_prog_session_data_hash,
				   &id, sizeof(id),
				   &data, sizeof(data), 0);
	if (err) {
		bbdd_util_fmterr(error,
				 "Failed to look up BPF session data for id %u: %s",
				 id, strerror(-err));
		return NULL;
	}

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)							\
	if (bbdd_bpf_add_stat(obj, #NAME, data.diag_stats.NAME, error))	\
		goto err;

	BBDD_SESSION_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_bpf_session_stats_json(struct bbdd_bpf *bpf,
						uint32_t id,
						char **error)
{
	struct bbdd_prog_session_data data;
	struct json_object *obj;
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_prog_session_data_hash,
				   &id, sizeof(id),
				   &data, sizeof(data), 0);
	if (err) {
		bbdd_util_fmterr(error,
				 "Failed to look up BPF session data for id %u: %s",
				 id, strerror(-err));
		return NULL;
	}

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)							\
	if (bbdd_bpf_add_stat(obj, #NAME, data.stats.NAME, error))	\
		goto err;

	BBDD_SESSION_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

static int bbdd_bpf_session_set_mark(const struct bbdd_bpf_session *bsess,
				     char **error)
{
	uint32_t mark = bsess->gen_id;
	int rc;

	rc = setsockopt(bsess->sock_fd, SOL_SOCKET, SO_MARK,
			&mark, sizeof(mark));
	if (rc < 0) {
		bbdd_util_fmterr(error, "setsockopt(SO_MARK): %m");
		return -1;
	}
	return 0;
}

enum { BBDD_BPF_NS_PER_US = 1 * 1000 };

static int __bbdd_bpf_session_update(struct bbdd_bpf *bpf,
				     const struct bbdd_d_session *dsess,
				     struct bbdd_bpf_session *bsess,
				     bool add, char **error)
{
	uint32_t min_interval_us;
	uint32_t max_interval_us;
	uint32_t tbid = 0;    // xxx VRF support
	uint32_t flags = BPF_FIB_LOOKUP_SRC;
	uint32_t interval_us;
	uint32_t fwd_ifindex;
	int rc;

	bsess->gen_id++;

	/* system MUST NOT transmit BFD Control packets at an interval less than
	 * the larger of bfd.DesiredMinTxInterval and bfd.RemoteMinRxInterval,
	 * less applied jitter. */
	interval_us = MAX(dsess->local.min_tx_us, dsess->remote.min_rx_us);

	/* Jitter is x0.75..x0.1, but if detect_mult=1, it's x0.75..x0.9. */
	min_interval_us = interval_us * 75 / 100;
	if (dsess->local.detect_mult == 1)
		max_interval_us = interval_us * 90 / 100;
	else
		max_interval_us = interval_us;

	rc = bbdd_bpf_session_set_mark(bsess, error);
	if (rc != 0)
		return rc;

	if (tbid != 0)
		flags |= BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID;

	if (dsess->ifindex != 0) {
		fwd_ifindex = dsess->ifindex;
		flags |= BPF_FIB_LOOKUP_OUTPUT;
	} else {
		fwd_ifindex = bpf->conf.veth_tx_ifindex;
	}

	if (add)
		rc = bbdd_bpf_session_conf_add(bpf, dsess, bsess, fwd_ifindex,
					       tbid, flags, min_interval_us,
					       max_interval_us, error);
	else
		rc = bbdd_bpf_session_conf_update(bpf, dsess, bsess, fwd_ifindex,
						  tbid, flags, min_interval_us,
						  max_interval_us, error);
	if (rc != 0)
		return rc;

	rc = bbdd_bpf_session_inject_pkt(dsess, bsess,
					 bpf->conf.veth_tx_ifindex, 0,
					 error);
	if (rc != 0)
		goto del_session;

	return 0;

	/* There's no reliable way to roll back everything, and e.g. rolling
	 * back the mark is pointless. Unless everything lines up just right,
	 * the session is broken. Even if the standard allowed to do something
	 * like add a new session with new id and then remove the old one, when
	 * the removal fails, we've got two sessions and it's broken. The only
	 * thing that we clean up is the session add. */
del_session:
	if (add)
		bbdd_bpf_session_conf_delete(bpf, dsess->local.discr);
	return rc;
}

static int bbdd_d_session_open_sock(const struct bbdd_d_session *dsess,
				    uint32_t veth_tx_ifindex, char **error)
{
	uint16_t proto;
	union {
		struct sockaddr sa;
		struct sockaddr_ll sll;
	} sa = {};
	int fd;
	int rc;

	switch (dsess->dst.sa.sa_family) {
	case AF_INET:
		proto = ETH_P_IP;
		break;
	case AF_INET6:
		proto = ETH_P_IPV6;
		break;
	default:
		bbdd_util_fmterr(error, "Unsupported address family %d",
				 dsess->src.sa.sa_family);
		return -1;
	}

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(proto));
	if (fd < 0) {
		bbdd_util_fmterr(error, "socket(AF_PACKET): %m");
		return -1;
	}

	sa.sll.sll_family   = AF_PACKET;
	sa.sll.sll_protocol = htons(proto);
	sa.sll.sll_ifindex  = (int)veth_tx_ifindex;

	rc = bind(fd, &sa.sa, sizeof(sa));
	if (rc < 0) {
		bbdd_util_fmterr(error, "bind(AF_PACKET): %m");
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return -1;
}

struct bbdd_bpf_session *
bbdd_bpf_session_add(struct bbdd_bpf *bpf,
		     const struct bbdd_d_session *dsess,
		     char **error)
{
	struct bbdd_bpf_session *bsess;
	int sock_fd;
	int err;

	bsess = malloc(sizeof(*bsess));
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "%m");
		return NULL;
	}

	sock_fd = bbdd_d_session_open_sock(dsess, bpf->conf.veth_tx_ifindex,
					   error);
	if (sock_fd < 0) {
		err = sock_fd;
		goto free_bsess;
	}

	*bsess = (struct bbdd_bpf_session) {
		.gen_id = 0,
		.sock_fd = sock_fd,
	};

	err = __bbdd_bpf_session_update(bpf, dsess, bsess, true, error);
	if (err != 0)
		goto close_sock;

	return bsess;

close_sock:
	close(sock_fd);
free_bsess:
	free(bsess);
	return NULL;
}

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    const struct bbdd_d_session *dsess,
			    struct bbdd_bpf_session *bsess,
			    char **error)
{
	return __bbdd_bpf_session_update(bpf, dsess, bsess, false, error);
}

void bbdd_bpf_session_del(struct bbdd_bpf *bpf,
			  const struct bbdd_d_session *dsess,
			  struct bbdd_bpf_session *bsess)
{
	/* The packet will be dropped by the looper when no matching session is
	 * found. */

	bbdd_bpf_session_conf_delete(bpf, dsess->local.discr);

	close(bsess->sock_fd);
	free(bsess);
}
