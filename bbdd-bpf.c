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
#include <fcntl.h>
#include <json-c/json_object.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <uthash.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-nl.h"
#include "bbdd-prog.h"
#include "bbdd-util.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "bbdd-prog.skel.h"
#pragma GCC diagnostic pop

/* Interface between bbdd_bpf_rb_recv() and bbdd_bpf_rb_handle(). */
struct bbdd_bpf_rb_context {
	struct bbdd_bpf *bpf;
	struct ring_buffer *rb;
	struct bbdd_nl *nl;
	struct bbdd_sess_dir *sdir;
	struct bbdd_mon *mon;
};

#define SOCK(AF, PORT, NAME) \
		struct bbdd_sock NAME##_sk;

struct bbdd_bpf_sockets {
	BBDD_PROG_RECV_SOCKETS(SOCK)
};

#undef SOCK

struct bbdd_bpf {
	/* Some of the conf information is not strictly necessary to keep around
	 * or duplicated in the attachments, but it's easier to keep it all. */
	struct bbdd_bpf_global_config conf;
	struct bbdd_bpf_session *sdir;

	struct bbdd_prog *skel;
	struct bbdd_bpf_rb_context *rb_ctx;

	struct bbdd_bpf_sockets sockets;
	struct bpf_link *sk_lookup_link;

	struct bbdd_prog_global_diag_stats diag_stats;
};

enum bbdd_bpf_session_state {
	BBDD_BPF_SESSION_STATE_STABLE,
	BBDD_BPF_SESSION_STATE_AWAIT_FINAL,
	BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL,
};

/* Per-session data. */
struct bbdd_bpf_session {
	uint32_t discr;
	uint32_t gen_id;
	int sock_fd;

	/* Certain configuration changes prompt a poll sequence. These changes
	 * only become effective when the poll sequence is closed by arrival of
	 * a final packet. The issue is that a final packet doesn't otherwise
	 * designate which poll packet it responds to. If we allowed changing
	 * the session configuration at any time, we wouldn't know which
	 * settings are safe to apply.
	 *
	 * We therefore have the following objects in play:
	 *
	 * - USER: bbdd_d_session.local configuration: What the user wants.
	 *
	 * - EFF: bbdd_bpf_session effective configuration: What we use to
         *   configure transmit and receive timers.
	 *
	 * - POLL: bbdd_bpf_session poll configuration: The configuration change
         *   that prompted the poll sequence.
	 *
	 * - MARK: A marker that more changes are enqueued.
	 *
	 * The update process is as follows:
	 *
	 * 1) As USER config changes in a way that requires a poll sequence:
	 *    - If there is no POLL config yet:
	 *      - Apply POLL = USER.
	 *      - Start sending Poll packets
	 *    - Otherwise set MARK.
	 *
	 * 2) As Final packet arrives:
	 *    - Apply EFF = POLL and update data path.
	 *    - Stop sending Poll packets.
	 *    - Set expected packet to Final.
	 *    - Keep POLL
	 *
	 * 3) As the first non-Final packet arrives, we know the poll sequence
	 *    is terminated: the remote end has seen our configuration and all
	 *    our poll packets. The poll sequence channel is free again. Then:
	 *    - Remove POLL
	 *    - If there is MARK, fetch new USER config and goto 1.
	 */
	enum bbdd_bpf_session_state bstate;
	struct bbdd_d_session_data_timing eff_timing;
	struct bbdd_d_session_data_timing poll_timing;
	const struct bbdd_d_session_data_timing *qd_timing;

	bool timer_armed;

	struct bbdd_prog_session_data_stats stats;
	struct bbdd_prog_session_data_diag_stats diag_stats;

	UT_hash_handle hh;
};

static struct bbdd_bpf_session *
bbdd_bpf_sdir_get_session(struct bbdd_bpf *bpf, uint32_t discr)
{
	struct bbdd_bpf_session *bsess;

	HASH_FIND_INT(bpf->sdir, &discr, bsess);
	return bsess;
}

static int bbdd_bpf_print(enum libbpf_print_level level,
			  const char *fmt, va_list args)
{
	if ((int)level <= bbdd_env.verbosity)
		vfprintf(stderr, fmt, args);
	return 0;
}

static struct bbdd_bfd_pkt
bbdd_bpf_make_packet(uint32_t my_disc,
		     const struct bbdd_d_session_data_timing *timing,
		     const struct bbdd_d_session_state_end *state,
		     uint32_t your_disc, uint8_t flags)
{
	enum { v1 = 1 };
	return (struct bbdd_bfd_pkt) {
		.version_diag = (v1 << 5) | (uint8_t) state->diag,
		.state_bits = (uint8_t) (state->state << 6 | flags),
		.detection_multiplier = timing->detect_mult,
		.length = sizeof(struct bbdd_bfd_pkt),
		.my_disc = htonl(my_disc),
		.your_disc = htonl(your_disc),
		.desired_tx = htonl(timing->min_tx_us),
		.required_rx = htonl(timing->min_rx_us),
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
	struct bbdd_d_session_data_timing *timing;
	struct bbdd_bfd_pkt bfd;
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

	/* If the timing is such that a system receiving a Poll Sequence wishes
	 * to change the parameters, the new parameter values MAY be carried in
	 * packets with the Final (F) bit set, even if the Poll Sequence has not
	 * yet been sent. */
	switch (bsess->bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		timing = &bsess->eff_timing;
		break;
        case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		timing = &bsess->poll_timing;
		break;
	}

	assert(timing->detect_mult != 0);
	bfd = bbdd_bpf_make_packet(dsess->local.discr, timing,
				   &dsess->local.state,
				   dsess->remote.discr, bfd_flags);

	dst_sa.sll.sll_family  = AF_PACKET;
	dst_sa.sll.sll_ifindex = (int)tx_ifindex;
	dst_sa.sll.sll_halen   = ETH_ALEN;
	memset(dst_sa.sll.sll_addr, 0xff, ETH_ALEN);

	if (dsess->dst.sa.sa_family == AF_INET) {
		struct {
			struct iphdr ip;
			struct udphdr udp;
			struct bbdd_bfd_pkt bfd;
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
			struct bbdd_bfd_pkt bfd;
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
bbdd_bpf_parse_packet(struct bbdd_bpf *bpf,
		      struct bbdd_bpf_session *bsess,
		      const struct bbdd_bfd_pkt *packet,
		      struct bbdd_d_session_data *remote_data,
		      bool *poll, bool *final)
{
	uint8_t bits = bbdd_bfd_pkt_bits(packet);
	uint32_t remote_discr = ntohl(packet->my_disc);
	uint32_t local_discr = ntohl(packet->your_disc);
	enum bbdd_bfd_pkt_state state;

	/* Note: Version and length are validated in BPF. */

	state = bbdd_bfd_pkt_state(packet);

	if (packet->required_echo_rx != 0 ||
	    bits & (BBDD_BFD_PKT_BIT_AUTH |
		    BBDD_BFD_PKT_BIT_DEMAND)) {
		++bsess->diag_stats.rx_unsupported;
		return -1;
	}

	if (bits & BBDD_BFD_PKT_BIT_MULTI) {
		/* Technically this is also "not supported", but the
		 * original RFC call this out explicitly, so let's have an
		 * explicit counter. */
		++bsess->diag_stats.rx_multipoint_not_0;
		return -1;
	}

	if (packet->detection_multiplier == 0) {
		++bsess->diag_stats.rx_detection_multiplier_0;
		return -1;
	}

	if (remote_discr == 0) {
		++bsess->diag_stats.rx_my_discr_0;
		return -1;
	}

	if (local_discr == 0 &&
	    state != BBDD_BFD_PKT_STATE_ADMINDOWN &&
	    state != BBDD_BFD_PKT_STATE_DOWN) {
		++bsess->diag_stats.rx_your_discr_0_not_down;
		return -1;
	}

	if (remote_discr != 0 && remote_data->discr != remote_discr) {
		bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: remote discr %u",
				    bsess->discr, remote_discr);
		remote_data->discr = remote_discr;
	}
	remote_data->timing.min_rx_us = ntohl(packet->required_rx);
	remote_data->timing.min_tx_us = ntohl(packet->desired_tx);
	remote_data->timing.detect_mult = packet->detection_multiplier;
	remote_data->state.state = state;
	remote_data->state.diag = bbdd_bfd_pkt_diag(packet);

	*poll = bits & BBDD_BFD_PKT_BIT_POLL;
	*final = bits & BBDD_BFD_PKT_BIT_FINAL;

	return 0;
}

static uint8_t bbdd_bpf_get_rx_expect_bfd_flags(enum bbdd_bpf_session_state bstate)
{
	switch (bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		return 0;

	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
		return 0;

	/* When we are waiting for non-Final packet, set expected packet
	 * to final and catch mismatches. */
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		return BBDD_BFD_PKT_BIT_FINAL;
	}

	assert(!"bbdd_bpf_get_rx_expect_bfd_flags");
	__builtin_unreachable();
}

static uint8_t bbdd_bpf_get_inject_bfd_flags(enum bbdd_bpf_session_state bstate)
{
	switch (bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		return 0;

	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
		return BBDD_BFD_PKT_BIT_POLL;

	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		return 0;
	}

	assert(!"bbdd_bpf_get_inject_bfd_flags");
	__builtin_unreachable();
}

static int bbdd_bpf_session_conf_update(struct bbdd_bpf *bpf,
					const struct bbdd_d_session *dsess,
					struct bbdd_bpf_session *bsess,
					uint32_t ifindex,
					uint32_t tbid,
					uint32_t fib_flags,
					uint32_t min_interval_us,
					uint32_t max_interval_us,
					uint32_t detect_time_us,
					bool rearm_timer,
					char **error)
{
	bool admdown = dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN;

	uint8_t bfd_flags = bbdd_bpf_get_rx_expect_bfd_flags(bsess->bstate);
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
		.bpf_fib_lookup_flags = fib_flags,
		.min_interval_us = min_interval_us,
		.max_interval_us = max_interval_us,
		.detect_time_us = detect_time_us,
		.gen_id = bsess->gen_id,
		.admin_down = admdown,
		.rearm_timer = rearm_timer,
		.ttl = dsess->ttl,
		.rx_expect = bbdd_bpf_make_packet(dsess->remote.discr,
						  &dsess->remote.timing,
						  &dsess->remote.state,
						  dsess->local.discr, bfd_flags),
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
				     uint32_t fib_flags,
				     uint32_t min_interval_us,
				     uint32_t max_interval_us,
				     uint32_t detect_time_us,
				     bool rearm_timer,
				     char **error)
{
	struct bbdd_prog_session_data data = {};
	uint32_t discr = dsess->local.discr;
	int err;

	err = bbdd_bpf_session_conf_update(bpf, dsess, bsess, ifindex,
					   tbid, fib_flags, min_interval_us,
					   max_interval_us, detect_time_us,
					   rearm_timer, error);
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
	const struct bbdd_d_session_data_timing *eff_timing = &bsess->eff_timing;
	uint32_t min_interval_us;
	uint32_t max_interval_us;
	uint32_t detect_time_us;
	uint32_t interval_us;
	uint32_t tbid = dsess->vrf_table;
	uint32_t fib_flags = BPF_FIB_LOOKUP_SRC;
	uint32_t fwd_ifindex;
	uint8_t bfd_flags;
	bool downish;
	bool admdown;
	bool down;
	int rc;

	bsess->gen_id++;

	// xxx the RFC requires only Down to be treated specially, but it's
	// odd to me that an admin down session would need to flood packet
	// full speed. For now treat both the same, but this needs
	// attention to resolve for good.
	downish = dsess->local.state.state == BBDD_BFD_PKT_STATE_DOWN ||
		  dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN;
	down = dsess->local.state.state == BBDD_BFD_PKT_STATE_DOWN;
	admdown = dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN;

	if (downish)
		/* If the session goes Down, the transmission of Echo
		 * packets (if any) ceases, and the transmission of Control
		 * packets goes back to the slow rate. */
		interval_us = bbdd_prog_slow_interval_us;
	else
		/* system MUST NOT transmit BFD Control packets at an
		 * interval less than the larger of bfd.RemoteMinRxInterval
		 * and bfd.DesiredMinTxInterval, less applied jitter. */
		interval_us = MAX(eff_timing->min_tx_us,
				  dsess->remote.timing.min_rx_us);

	/* In Asynchronous mode, the Detection Time calculated in the local
	 * system is equal to the value of Detect Mult received from the remote
	 * system, multiplied by the agreed transmit interval of the remote
	 * system (the greater of bfd.RequiredMinRxInterval and the last
	 * received Desired Min TX Interval).
	 */
	assert(dsess->remote.timing.detect_mult != 0);
	detect_time_us = MAX(eff_timing->min_rx_us,
			     dsess->remote.timing.min_tx_us);
	if (detect_time_us > UINT32_MAX / dsess->remote.timing.detect_mult)
		detect_time_us = UINT32_MAX;
	else
		detect_time_us *= dsess->remote.timing.detect_mult;

	/* Jitter is x0.75..x0.1, but if detect_mult=1, it's x0.75..x0.9.
	 * For downish sessions, just take the slow rate verbatim. */
	if (downish) {
		min_interval_us = max_interval_us = interval_us;
	} else {
		min_interval_us = interval_us * 75 / 100;
		if (eff_timing->detect_mult == 1)
			max_interval_us = interval_us * 90 / 100;
		else
			max_interval_us = interval_us;
	}

	rc = bbdd_bpf_session_set_mark(bsess, error);
	if (rc != 0)
		return rc;

	if (tbid != 0)
		fib_flags |= BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID;

	if (dsess->ifindex != 0) {
		fwd_ifindex = dsess->ifindex;
		fib_flags |= BPF_FIB_LOOKUP_OUTPUT;
	} else {
		fwd_ifindex = bpf->conf.veth_tx_ifindex;
	}

	bool rearm_timer = !(down || admdown);
	if (add)
		rc = bbdd_bpf_session_conf_add(bpf, dsess, bsess, fwd_ifindex,
					       tbid, fib_flags,
					       min_interval_us,
					       max_interval_us,
					       detect_time_us,
					       rearm_timer, error);
	else
		rc = bbdd_bpf_session_conf_update(bpf, dsess, bsess, fwd_ifindex,
						  tbid, fib_flags,
						  min_interval_us,
						  max_interval_us,
						  detect_time_us,
						  rearm_timer, error);
	if (rc != 0)
		return rc;

	bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: Injecting packet, gen_id %u",
			    dsess->local.discr, bsess->gen_id);

	bfd_flags = bbdd_bpf_get_inject_bfd_flags(bsess->bstate);
	rc = bbdd_bpf_session_inject_pkt(dsess, bsess,
					 bpf->conf.veth_tx_ifindex,
					 bfd_flags, error);
	if (rc != 0)
		goto del_session;

	if (rearm_timer > bsess->timer_armed) {
		bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: Arming timer",
				    dsess->local.discr);
		rc = bbdd_bpf_session_inject_pkt(dsess, bsess,
						 bpf->conf.veth_rx_ifindex,
						 0, error);
		if (rc != 0)
			goto del_session;
	}
	bsess->timer_armed = rearm_timer;

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

static void
bbdd_bpf_rb_handle_no_neigh(const struct bbdd_bpf_rb_elem_tx_no_neigh *elem,
			    struct bbdd_nl *nl)
{
	struct bbdd_sockaddr addr = {};
	char *error;
	int err;

	err = bbdd_bpf_addr_to_sockaddr(elem->ethtype, &elem->addr, &addr,
					"BBDD_BPF_RB_ELEM_TX_NO_NEIGH",
					&error);
	if (err != 0)
		goto error;

	err = bbdd_nl_refresh_neigh(nl, (uint32_t)elem->ifindex, &addr, &error);
	if (err != 0)
		goto error;
	return;

error:
	bbdd_util_printerr(&error, "no neighbor");
}

/* Return number of found sessions, or < 0 on error. The last matched session,
 * if any, is returned through ret_discr. */
static int
bbdd_bpf_rb_discr0_find_session(uint32_t *ret_discr,
				struct bbdd_sess_dir *sdir,
				uint32_t ifindex, uint8_t ttl,
				bool multihop, uint32_t table,
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

		if (dsess->vrf_table != table)
			continue;

		if (ttl < dsess->ttl)
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

static void bbdd_bpf_session_call_update(struct bbdd_bpf *bpf,
					 struct bbdd_d_session *dsess,
					 struct bbdd_bpf_session *bsess)
{
	char *error;
	int err;

	err = __bbdd_bpf_session_update(bpf, dsess, bsess, false, &error);
	if (err != 0)
		bbdd_util_printerr(&error, "session %u state change: Failed to update session",
				   dsess->local.discr);
}

static void bbdd_bpf_session_state_changed(struct bbdd_bpf *bpf,
					   struct bbdd_d_session *dsess,
					   struct bbdd_bpf_session *bsess)
{
	bbdd_bpf_session_call_update(bpf, dsess, bsess);
	bbdd_d_session_state_changed(dsess, bpf, bpf->rb_ctx->mon);
}

static void bbdd_bpf_handle_packet_got_final(struct bbdd_bpf *bpf,
					     struct bbdd_d_session *dsess,
					     struct bbdd_bpf_session *bsess)
{
	bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: await non-final",
			    dsess->local.discr);
	bsess->bstate = BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL;
	bbdd_bpf_session_call_update(bpf, dsess, bsess);
}

static void bbdd_bpf_handle_packet_got_non_final(struct bbdd_bpf *bpf,
						 struct bbdd_d_session *dsess,
						 struct bbdd_bpf_session *bsess)
{
	/* The non-final packet concludes the poll sequence and we can check if
	 * there's another state to poll. */

	bsess->eff_timing = bsess->poll_timing;

	if (bsess->qd_timing == NULL) {
		bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: stable",
				    dsess->local.discr);
		bsess->bstate = BBDD_BPF_SESSION_STATE_STABLE;
	} else {
		bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: queued timing, await final",
				    dsess->local.discr);
		bsess->poll_timing = *bsess->qd_timing;
		bsess->qd_timing = NULL;
		bsess->bstate = BBDD_BPF_SESSION_STATE_AWAIT_FINAL;
	}

	bbdd_bpf_session_call_update(bpf, dsess, bsess);
}

static void
bbdd_bpf_handle_packet(struct bbdd_bpf *bpf,
		       struct bbdd_sess_dir *sdir,
		       uint32_t local_discr,
		       const struct bbdd_bfd_pkt *packet,
		       uint16_t skb_len, uint8_t ttl)
{
	struct bbdd_d_session_data old_local;
	struct bbdd_d_session_data old_remote;
	struct bbdd_bpf_session *bsess;
	struct bbdd_d_session *dsess;
	bool final_recvd;
	bool poll_recvd;
	int err;

	/* Errors here are problematic, but not worth killing the daemon
	 * over. Just eat them. */

	dsess = bbdd_sess_dir_get_session(sdir, local_discr);
	bsess = bbdd_bpf_sdir_get_session(bpf, local_discr);
	if (dsess == NULL || bsess == NULL) {
		/* I think this can come up when BPF found a session and emit an
		 * event, but before we got to process it, the session gets
		 * deleted. So don't even print anything. */
		return;
	}

	++bsess->stats.rx_packets;
	bsess->stats.rx_bytes += skb_len;

	/* For admin down sessions where your_disc is given, we don't even get
	 * to see these packets, because BPF shoots them down. But when
	 * your_disc == 0, the packets are processed here, and we need to shoot
	 * them down ourselves.
	 */
	if (dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN) {
		++bsess->diag_stats.rx_admin_down;
		return;
	}

	/* RFC: [For single-hop sessions] TTL or Hop Count MUST be set to the
	 * maximum on transmit, and checked to be equal to the maximum value on
	 * reception.
	 *
	 * We always set TTL to 255, and let the user configure per-session what
	 * value of incoming TTL they tolerate. The RFC doesn't directly say
	 * that non-matching packets must be dropped, but what else.
	 */
	if (dsess->ttl > ttl) {
		++bsess->diag_stats.rx_ttl_low;
		return;
	}

	old_local = dsess->local;
	old_remote = dsess->remote;

	err = bbdd_bpf_parse_packet(bpf, bsess, packet, &dsess->remote,
				    &poll_recvd, &final_recvd);
	if (err)
		return;

	if (dsess->remote.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN) {
		if (dsess->local.state.state != BBDD_BFD_PKT_STATE_DOWN) {
			dsess->local.state.state = BBDD_BFD_PKT_STATE_DOWN;
			dsess->local.state.diag = BBDD_BFD_PKT_DIAG_DOWN;
			// xxx should we at some point reset the remote
			// discriminator? Otherwise we'll keep referring to
			// a your_disc that may be long gone.
		}
	} else {
		switch (dsess->local.state.state) {
		case BBDD_BFD_PKT_STATE_ADMINDOWN:
			break;

		case BBDD_BFD_PKT_STATE_DOWN:
			if (dsess->remote.state.state ==
				    BBDD_BFD_PKT_STATE_DOWN) {
				dsess->local.state.state =
					BBDD_BFD_PKT_STATE_INIT;
				dsess->local.state.diag =
					BBDD_BFD_PKT_DIAG_NOTHING;
			} else if (dsess->remote.state.state ==
				    BBDD_BFD_PKT_STATE_INIT) {
				dsess->local.state.state =
					BBDD_BFD_PKT_STATE_UP;
				dsess->local.state.diag =
					BBDD_BFD_PKT_DIAG_NOTHING;
			}
			break;

		case BBDD_BFD_PKT_STATE_INIT:
			if (dsess->remote.state.state ==
				    BBDD_BFD_PKT_STATE_INIT ||
			    dsess->remote.state.state ==
				    BBDD_BFD_PKT_STATE_UP) {
				dsess->local.state.state =
					BBDD_BFD_PKT_STATE_UP;
				dsess->local.state.diag =
					BBDD_BFD_PKT_DIAG_NOTHING;
			}
			break;

		case BBDD_BFD_PKT_STATE_UP:
			if (dsess->remote.state.state ==
				    BBDD_BFD_PKT_STATE_DOWN) {
				dsess->local.state.state =
					BBDD_BFD_PKT_STATE_DOWN;
				dsess->local.state.diag =
					BBDD_BFD_PKT_DIAG_DOWN;
			}
			break;
		}
	}

	if (memcmp(&old_local, &dsess->local, sizeof(old_local)) != 0 ||
	    memcmp(&old_remote, &dsess->remote, sizeof(old_remote)) != 0)
		bbdd_bpf_session_state_changed(bpf, dsess, bsess);

	if (poll_recvd) {
		char *error;

		bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: Injecting final packet",
				    dsess->local.discr);
		err = bbdd_bpf_session_inject_pkt(dsess, bsess,
						  bpf->conf.veth_tx_ifindex,
						  BBDD_BFD_PKT_BIT_FINAL,
						  &error);
		if (err != 0)
			bbdd_util_printerr(&error, "Failed to respond to a poll packet");
	}

	switch (bsess->bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		break;

	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
		if (final_recvd)
			bbdd_bpf_handle_packet_got_final(bpf, dsess, bsess);
		break;

	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		if (!final_recvd)
			bbdd_bpf_handle_packet_got_non_final(bpf, dsess, bsess);
		break;
	}
}

static void
bbdd_bpf_rb_handle_discr_0(const struct bbdd_bpf_rb_elem_rx_discr_0 *elem,
			   struct bbdd_bpf *bpf, struct bbdd_sess_dir *sdir,
			   struct bbdd_nl *nl)
{
	struct bbdd_sockaddr saddr;
	struct bbdd_sockaddr daddr;
	uint32_t discr;
	uint32_t table;
	int err;
	unsigned int nmatch;
	char *error;

	err = bbdd_nl_get_l3_master(nl, elem->ifindex, &table, &error);
	if (err != 0)
		goto error;

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
					      elem->ifindex, elem->ttl,
					      elem->multihop, table,
					      &saddr, &daddr, &error);
	if (err < 0)
		goto error;

	nmatch = (unsigned int) err;

	if (nmatch != 1) {
		++bpf->diag_stats.rx_no_unique_session;
		return;
	}

	return bbdd_bpf_handle_packet(bpf, sdir, discr, &elem->packet,
				      elem->skb_len, elem->ttl);

error:
	bbdd_util_printerr(&error, "`your_discr' of 0");
}

static void
bbdd_bpf_rb_handle_unx_pkt(const struct bbdd_bpf_rb_elem_rx_unx_pkt *elem,
			   struct bbdd_bpf *bpf,
			   struct bbdd_sess_dir *sdir)
{
	uint32_t local_discr = ntohl(elem->packet.your_disc);

	return bbdd_bpf_handle_packet(bpf, sdir, local_discr, &elem->packet,
				      elem->skb_len, elem->ttl);
}

static void
bbdd_bpf_rb_handle_timeout(const struct bbdd_bpf_rb_elem_rx_timeout *elem,
			   struct bbdd_bpf *bpf,
			   struct bbdd_sess_dir *sdir)
{
	uint32_t local_discr = elem->discr;
	struct bbdd_bpf_session *bsess;
	struct bbdd_d_session *dsess;

	dsess = bbdd_sess_dir_get_session(sdir, local_discr);
	bsess = bbdd_bpf_sdir_get_session(bpf, local_discr);
	if (dsess == NULL || bsess == NULL) {
		/* As when processing unexpected packets, this can probably
		 * come up due to a race. */
		return;
	}

	/* If Demand mode is not active, and a period of time equal to the
	 * Detection Time passes without receiving a BFD Control packet
	 * from the remote system, and bfd.SessionState is Init or Up, the
	 * session has gone down -- the local system MUST set
	 * bfd.SessionState to Down and bfd.LocalDiag to 1 (Control
	 * Detection Time Expired).
	 */
	if (dsess->local.state.state == BBDD_BFD_PKT_STATE_INIT ||
	    dsess->local.state.state == BBDD_BFD_PKT_STATE_UP) {
		dsess->local.state.state = BBDD_BFD_PKT_STATE_DOWN;
		dsess->local.state.diag = BBDD_BFD_PKT_DIAG_TIME_EXPIRED;

		bbdd_bpf_session_state_changed(bpf, dsess, bsess);
	}
}

static struct json_object *
bbdd_bpf_jrpc_addr_obj(uint16_t ethtype, const struct bbdd_bpf_addr *bpf_addr,
		       char **error)
{
	char buf[INET6_ADDRSTRLEN];
	struct bbdd_sockaddr addr;
	int err;

	err = bbdd_bpf_addr_to_sockaddr(ethtype, bpf_addr, &addr, "monitor",
					error);
	if (err != 0)
		return NULL;

	err = bbdd_sockaddr_ntop(&addr, buf, sizeof(buf), error);
	if (err != 0)
		return NULL;

	return bbdd_c_jrpc_addr_obj(buf, addr.sa.sa_family);
}

static struct json_object *
bbdd_bpf_rb_format_packet_bitarr(const struct bbdd_bfd_pkt *packet)
{
	struct json_object *obj;
	struct json_object *f;
	uint8_t bits;
	int err;

	obj = json_object_new_array();
	if (obj == NULL)
		return obj;

	bits = bbdd_bfd_pkt_bits(packet);

#define APPEND(BIT, NAME, name) do {				\
		if (!(bits & BBDD_BFD_PKT_BIT_ ## NAME))	\
			break;					\
								\
		f = json_object_new_string(#name);		\
		if (f == NULL)					\
			goto err;				\
								\
		err = json_object_array_add(obj, f);		\
		if (err != 0)					\
			goto err;				\
		f = NULL;					\
		bits &= ~BBDD_BFD_PKT_BIT_ ## NAME;		\
	} while (0);

	BBDD_BFD_PKT_BITS(APPEND);
	if (bits != 0)
		fprintf(stderr, "unformatted bits: %#x\n", bits);
	return obj;

#undef APPEND

err:
	json_object_put(obj);
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_bfd_pkt(const struct bbdd_bfd_pkt *packet, char **error)
{
	enum bbdd_bfd_pkt_state state;
	enum bbdd_bfd_pkt_diag diag;
	struct json_object *obj;
	struct json_object *bitarr;
	int rc;

	obj = json_object_new_object();
	if (obj == NULL)
		goto oom;

	bitarr = bbdd_bpf_rb_format_packet_bitarr(packet);
	if (bitarr == NULL)
		goto oom;

	rc = json_object_object_add(obj, "bits", bitarr);
	if (rc != 0)
		goto oom;
	bitarr = NULL;

	state = bbdd_bfd_pkt_state(packet);
	diag = bbdd_bfd_pkt_diag(packet);

	if (bbdd_jrpc_append_int(obj, "version",
				 bbdd_bfd_pkt_version(packet)) ||
	    bbdd_jrpc_append_str(obj, "state",
				 bbdd_d_bfd_state_to_str(state)) ||
	    bbdd_jrpc_append_str(obj, "diag",
				 bbdd_d_bfd_diag_to_str(diag)) ||
	    bbdd_jrpc_append_int(obj, "detect_mult",
				 packet->detection_multiplier) ||
	    bbdd_jrpc_append_int(obj, "my-disc",    ntohl(packet->my_disc)) ||
	    bbdd_jrpc_append_int(obj, "your-disc",  ntohl(packet->your_disc)) ||
	    bbdd_jrpc_append_int(obj, "desired-tx", ntohl(packet->desired_tx)) ||
	    bbdd_jrpc_append_int(obj, "required-rx",
				 ntohl(packet->required_rx)))
		goto oom;

	return obj;

oom:
	bbdd_util_fmterr(error, "%m");
	json_object_put(bitarr);
	json_object_put(obj);
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_tx_no_neigh(const struct bbdd_bpf_rb_elem_tx_no_neigh *elem,
			       char **error)
{
	struct json_object *addr_obj;
	struct json_object *params;
	struct json_object *obj;

	obj = bbdd_jrpc_new_notif("ringbuf:tx-no-neigh");
	if (obj == NULL)
		goto err;

	addr_obj = bbdd_bpf_jrpc_addr_obj(elem->ethtype, &elem->addr, error);
	if (addr_obj == NULL)
		goto put_obj;

	params = json_object_new_object();
	if (params == NULL)
		goto put_addr_obj;

	if (bbdd_jrpc_append_int(params, "ifindex", elem->ifindex) ||
	    bbdd_jrpc_append_obj(params, "addr", &addr_obj) ||
	    bbdd_jrpc_append_obj(obj, "params", &params))
		goto put_params;

	return obj;

put_params:
	json_object_put(params);
put_addr_obj:
	json_object_put(addr_obj);
put_obj:
	json_object_put(obj);
err:
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_rx_discr_0(
	const struct bbdd_bpf_rb_elem_rx_discr_0 *elem, char **error)
{
	struct json_object *src_obj;
	struct json_object *dst_obj;
	struct json_object *pkt_obj;
	struct json_object *params;
	struct json_object *obj;

	obj = bbdd_jrpc_new_notif("ringbuf:rx-discr-0");
	if (obj == NULL)
		goto err;

	src_obj = bbdd_bpf_jrpc_addr_obj(elem->ethtype, &elem->saddr, error);
	if (src_obj == NULL)
		goto put_obj;

	dst_obj = bbdd_bpf_jrpc_addr_obj(elem->ethtype, &elem->daddr, error);
	if (dst_obj == NULL)
		goto put_src_obj;

	pkt_obj = bbdd_bpf_rb_format_bfd_pkt(&elem->packet, error);
	if (pkt_obj == NULL)
		goto put_dst_obj;

	params = json_object_new_object();
	if (params == NULL)
		goto put_pkt_obj;

	if (bbdd_jrpc_append_int(params, "ifindex", elem->ifindex) ||
	    bbdd_jrpc_append_int(params, "skb-len", elem->skb_len) ||
	    bbdd_jrpc_append_int(params, "ttl", elem->ttl) ||
	    bbdd_jrpc_append_bool(params, "multihop", elem->multihop) ||
	    bbdd_jrpc_append_obj(params, "src", &src_obj) ||
	    bbdd_jrpc_append_obj(params, "dst", &dst_obj) ||
	    bbdd_jrpc_append_obj(params, "bfd", &pkt_obj) ||
	    bbdd_jrpc_append_obj(obj, "params", &params))
		goto put_params;

	return obj;

put_params:
	json_object_put(params);
put_pkt_obj:
	json_object_put(pkt_obj);
put_dst_obj:
	json_object_put(dst_obj);
put_src_obj:
	json_object_put(src_obj);
put_obj:
	json_object_put(obj);
err:
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_rx_unx_pkt(const struct bbdd_bpf_rb_elem_rx_unx_pkt *elem,
			      char **error)
{
	struct json_object *params;
	struct json_object *pkt_obj;
	struct json_object *obj;

	obj = bbdd_jrpc_new_notif("ringbuf:rx-unx-pkt");
	if (obj == NULL)
		return NULL;

	pkt_obj = bbdd_bpf_rb_format_bfd_pkt(&elem->packet, error);
	if (pkt_obj == NULL)
		goto put_obj;

	params = json_object_new_object();
	if (params == NULL)
		goto put_pkt_obj;

	if (bbdd_jrpc_append_int(params, "skb-len", elem->skb_len) ||
	    bbdd_jrpc_append_int(params, "ttl", elem->ttl) ||
	    bbdd_jrpc_append_obj(params, "bfd", &pkt_obj) ||
	    bbdd_jrpc_append_obj(obj, "params", &params))
		goto put_params;

	return obj;

put_params:
	json_object_put(params);
put_pkt_obj:
	json_object_put(pkt_obj);
put_obj:
	json_object_put(obj);
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_rx_timeout(
	const struct bbdd_bpf_rb_elem_rx_timeout *elem, char **error)
{
	struct json_object *params;
	struct json_object *obj;

	obj = bbdd_jrpc_new_notif("ringbuf:rx-timeout");
	if (obj == NULL)
		return NULL;

	params = json_object_new_object();
	if (params == NULL)
		goto put_obj;

	if (bbdd_jrpc_append_int(params, "discr", elem->discr) ||
	    bbdd_jrpc_append_obj(obj, "params", &params))
		goto put_params;

	return obj;

put_params:
	json_object_put(params);
put_obj:
	json_object_put(obj);
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bpf_rb_format_jrpc(const struct bbdd_bpf_rb_elem_head *head, char **error)
{
	const void *data = head;

	switch (head->type) {
	case BBDD_BPF_RB_ELEM_TX_NO_NEIGH:
		return bbdd_bpf_rb_format_tx_no_neigh(data, error);
	case BBDD_BPF_RB_ELEM_RX_DISCR_0:
		return bbdd_bpf_rb_format_rx_discr_0(data, error);
	case BBDD_BPF_RB_ELEM_RX_UNX_PKT:
		return bbdd_bpf_rb_format_rx_unx_pkt(data, error);
	case BBDD_BPF_RB_ELEM_RX_TIMEOUT:
		return bbdd_bpf_rb_format_rx_timeout(data, error);
	}

	bbdd_util_fmterr(error, "Unknown ring buffer element type %d",
			 head->type);
	return NULL;
}

static void bbdd_bpf_rb_mon_send(struct bbdd_bpf *bpf,
				 struct bbdd_mon *mon,
				 const struct bbdd_bpf_rb_elem_head *head)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_ringbuf;
	struct json_object *msg;
	char *error;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	msg = bbdd_bpf_rb_format_jrpc(head, &error);
	if (msg == NULL) {
		msg = bbdd_jrpc_new_error_int_error(NULL, error);
		if (msg == NULL)
			goto err;
	}

	bbdd_mon_send(mon, msg, topic);
	json_object_put(msg);
	return;

err:
	++bpf->diag_stats.monitor_error;
	bbdd_util_printerr(&error, "Failed to send monitor message");
}

static int bbdd_bpf_rb_handle(void *ctx, void *data, size_t)
{
	struct bbdd_bpf_rb_context *rb_ctx = ctx;
	const struct bbdd_bpf_rb_elem_head *head = data;

	bbdd_bpf_rb_mon_send(rb_ctx->bpf, rb_ctx->mon, head);

	switch (head->type) {
	case BBDD_BPF_RB_ELEM_TX_NO_NEIGH:
		bbdd_bpf_rb_handle_no_neigh(data, rb_ctx->nl);
		break;
	case BBDD_BPF_RB_ELEM_RX_DISCR_0:
		bbdd_bpf_rb_handle_discr_0(data, rb_ctx->bpf, rb_ctx->sdir,
					   rb_ctx->nl);
		break;
	case BBDD_BPF_RB_ELEM_RX_UNX_PKT:
		bbdd_bpf_rb_handle_unx_pkt(data, rb_ctx->bpf, rb_ctx->sdir);
		break;
	case BBDD_BPF_RB_ELEM_RX_TIMEOUT:
		bbdd_bpf_rb_handle_timeout(data, rb_ctx->bpf, rb_ctx->sdir);
		break;
	}
	return 0;
}

static int bbdd_bpf_rb_recv(struct bbdd_poll_ctx *, short, void *data, char **)
{
	struct bbdd_bpf_rb_context *rb_ctx = data;
	int ret;

	ret = ring_buffer__consume(rb_ctx->rb);
	if (ret < 0)
		return -1;

	return 0;
}

static struct bbdd_bpf_rb_context *
bbdd_bpf_rb_init(struct bbdd_prog *skel, struct bbdd_poll_ctx *pctx,
		 struct bbdd_nl *nl, struct bbdd_sess_dir *sdir,
		 struct bbdd_mon *mon, char **error)
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
	err = bbdd_poll_set_fd(pctx, rb_fd, POLLIN, bbdd_bpf_rb_recv, rb_ctx,
			       error);
	if (err != 0)
		goto free_ring_buffer;

	*rb_ctx = (struct bbdd_bpf_rb_context) {
		.rb = rb,
		.nl = nl,
		.sdir = sdir,
		.mon = mon,
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

static int bbdd_bpf_hook_create(int ifindex, char **error)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(struct bpf_tc_hook),
		.ifindex = ifindex,
		/* libbpf insists on this field even if we then use the hook to
		 * attach both ingress and egress programs. */
		.attach_point = BPF_TC_INGRESS,
	};
	int err;

	err = bpf_tc_hook_create(&hook);
	if (err != 0)
		bbdd_util_fmterr(error, "bpf_tc_hook_create: %s",
				 strerror(-err));
	return err;
}

static void bbdd_bpf_hook_destroy(int ifindex)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(struct bpf_tc_hook),
		.ifindex = ifindex,
		.attach_point = BPF_TC_INGRESS,
	};

	bpf_tc_hook_destroy(&hook);
}

static int bbdd_bpf_attach(struct bpf_program *prog, int ifindex,
			   enum bpf_tc_attach_point attach_point,
			   char **error)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = ifindex,
		.attach_point = attach_point,
	};
	struct bpf_tc_opts opts;
	int err;

	opts = (struct bpf_tc_opts) {
		.sz = sizeof(opts),
		.prog_fd = bpf_program__fd(prog),
		.handle = 1,
		.priority = 1,
	};

	err = bpf_tc_attach(&hook, &opts);
	if (err != 0)
		bbdd_util_fmterr(error, "bpf_tc_attach(ifindex=%u): %s",
				 ifindex, strerror(-err));
	return err;
}

static void bbdd_bpf_detach(struct bpf_program *prog, int ifindex,
			    enum bpf_tc_attach_point attach_point)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = ifindex,
		.attach_point = attach_point,
	};
	struct bpf_tc_opts opts = {
		.sz = sizeof(opts),
		.prog_fd = bpf_program__fd(prog),
		.handle = 1,
		.priority = 1,
	};
	bpf_tc_detach(&hook, &opts);
}

static int
bbdd_bpf_sock_open_udp(struct bbdd_sock *sock, uint16_t af, uint16_t port,
		       char **error)
{
	struct bbdd_sockaddr addr = {};

	addr.sa.sa_family = af;
	switch (af) {
	case AF_INET:
		addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin.sin_port = htons(port);
		addr.len = sizeof(addr.sin);
		break;
	case AF_INET6:
		addr.sin6.sin6_addr = in6addr_any;
		addr.sin6.sin6_port = htons(port);
		addr.len = sizeof(addr.sin6);
		break;
	}

	return bbdd_sock_open_udp(addr, sock, error);
}

static int bbdd_bpf_sockets_open(struct bbdd_bpf_sockets *sockets, char **error)
{
	ssize_t ndone = 0;
	int err;

#define OPEN(AF, PORT, NAME) {						\
		err = bbdd_bpf_sock_open_udp(&sockets->NAME ## _sk,	\
					     (AF), (PORT), error);	\
		if (err != 0)						\
			goto cleanup;					\
		++ndone;						\
	}
#define CLOSE(AF, PORT, NAME) {						\
		if (ndone-- > 0)					\
			bbdd_sock_close_udp(&sockets->NAME ## _sk);	\
	}

	BBDD_PROG_RECV_SOCKETS(OPEN);
	return 0;

cleanup:
	BBDD_PROG_RECV_SOCKETS(CLOSE);
	return err;

#undef CLOSE
#undef OPEN
}

static void bbdd_bpf_sockets_close(struct bbdd_bpf_sockets *sockets)
{
#define CLOSE(AF, PORT, NAME) bbdd_sock_close_udp(&sockets->NAME ## _sk);

	BBDD_PROG_RECV_SOCKETS(CLOSE);

#undef CLOSE
}

static int bbdd_bpf_sockets_attach_one(int sock_fd, int prog_fd)
{
	return setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
			  &prog_fd, sizeof(prog_fd));
}

static int bbdd_bpf_sockets_detach_one(int sock_fd)
{
	/* SO_DETACH_BPF ignores the optval, but sk_setsockopt() bounces us if
	 * it is < sizeof(int). So pass a dummy. */
	int dummy = 0;

	return setsockopt(sock_fd, SOL_SOCKET, SO_DETACH_BPF,
			  &dummy, sizeof(dummy));
}

static int bbdd_bpf_sockets_attach(struct bbdd_bpf *bpf, char **error)
{
	int prog_fd = bpf_program__fd(bpf->skel->progs.bbdd_recv);
	ssize_t ndone = 0;
	int err;

#define ATTACH(AF, PORT, NAME) {					\
		int sock_fd = bpf->sockets.NAME ## _sk.fd;		\
		err = bbdd_bpf_sockets_attach_one(sock_fd, prog_fd);	\
		if (err != 0)						\
			goto cleanup;					\
		++ndone;						\
	}
#define DETACH(AF, PORT, NAME) {					\
		if (ndone-- > 0) {					\
			int sock_fd = bpf->sockets.NAME ## _sk.fd;	\
			bbdd_bpf_sockets_detach_one(sock_fd);		\
		}							\
	}

	BBDD_PROG_RECV_SOCKETS(ATTACH);
	return 0;

cleanup:
	bbdd_util_fmterr(error, "Failed to attach socket program: %m");
	BBDD_PROG_RECV_SOCKETS(DETACH);
	return err;

#undef DETACH
#undef ATTACH
}

static void bbdd_bpf_sockets_detach(struct bbdd_bpf *bpf)
{
	int err = 0;

#define DETACH(AF, PORT, NAME) {					\
		int sock_fd = bpf->sockets.NAME ## _sk.fd;		\
		err = bbdd_bpf_sockets_detach_one(sock_fd) ?: err;	\
	}

	BBDD_PROG_RECV_SOCKETS(DETACH);
	if (err != 0)
		fprintf(stderr, "Failed to detach socket program: %m\n");

#undef DETACH
}

static int bbdd_bpf_sockmap_init(struct bbdd_bpf *bpf, char **error)
{
	int err;

#define UPDATE(AF, PORT, NAME) {					\
		uint32_t fd = bpf->sockets.NAME ## _sk.fd;		\
		uint32_t ix = BBDD_PROG_RECV_SOCK_ ## NAME ## _IX;	\
		err = bpf_map__update_elem(bpf->skel->maps.bbdd_bpf_sock_map, \
					   &ix, sizeof(ix),		\
					   &fd, sizeof(fd),		\
					   BPF_ANY);			\
		if (err != 0)						\
			goto err;					\
	}

	BBDD_PROG_RECV_SOCKETS(UPDATE)
	return 0;

err:
	bbdd_util_fmterr(error, "Failed to insert socket into sockmap: %s",
			 strerror(-err));
	return err;

#undef UPDATE
}

static void bbdd_bpf_sockmap_fini(struct bbdd_bpf *bpf)
{
	int err = 0;

#define DELETE(AF, PORT, NAME) {					\
		uint32_t ix = BBDD_PROG_RECV_SOCK_ ## NAME ## _IX;	\
		err = bpf_map__delete_elem(bpf->skel->maps.bbdd_bpf_sock_map, \
					   &ix, sizeof(ix), 0) ?: err;	\
	}

	BBDD_PROG_RECV_SOCKETS(DELETE);
	if (err != 0)
		fprintf(stderr, "Failed to remove sockets from sockmap: %s",
			strerror(-err));
#undef DELETE
}

static int bbdd_bpf_sk_lookup_attach(struct bbdd_bpf *bpf, char **error)
{
	int netns_fd;
	int err;

	err = bbdd_bpf_sockmap_init(bpf, error);
	if (err != 0)
		return err;

	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (netns_fd < 0) {
		bbdd_util_fmterr(error, "open(/proc/self/ns/net): %m");
		err = netns_fd;
		goto sockmap_fini;
	}

	bpf->sk_lookup_link = bpf_program__attach_netns(
			bpf->skel->progs.bbdd_sk_lookup, netns_fd);
	if (!bpf->sk_lookup_link) {
		bbdd_util_fmterr(error, "Failed to attach socket lookup program: %m");
		err = -1;
		goto close_netns_fd;
	}

	/* Close this always, we only need it to identify what to attach to. */
	close(netns_fd);
	return 0;

close_netns_fd:
	close(netns_fd);
sockmap_fini:
	bbdd_bpf_sockmap_fini(bpf);
	return err;
}

static void bbdd_bpf_sk_lookup_detach(struct bbdd_bpf *bpf)
{
	int err;

	err = bpf_link__destroy(bpf->sk_lookup_link);
	if (err != 0)
		fprintf(stderr, "Failed to detach socket lookup program: %s\n",
			strerror(-err));
}

struct bbdd_bpf *bbdd_bpf_create(struct bbdd_poll_ctx *pctx,
				 struct bbdd_nl *nl,
				 struct bbdd_bpf_global_config *conf,
				 struct bbdd_sess_dir *sdir,
				 struct bbdd_mon *mon,
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

	bpf->rb_ctx = bbdd_bpf_rb_init(bpf->skel, pctx, nl, sdir, mon, error);
	if (bpf->rb_ctx == NULL)
		goto destroy_prog;
	bpf->rb_ctx->bpf = bpf;

	bpf->skel->bss->bbdd_veth_tx_ifindex = (int)conf->veth_tx_ifindex;

	err = bbdd_bpf_hook_create(conf->veth_rx_ifindex, error);
	if (err != 0)
		goto free_rb_ctx;

	err = bbdd_bpf_hook_create(conf->veth_tx_ifindex, error);
	if (err != 0)
		goto destroy_rx_hook;

	/* Attach programs as the last step when everything else is
	 * prepared. */

	err = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_rx,
			      conf->veth_rx_ifindex, BPF_TC_INGRESS,
			      error);
	if (err != 0)
		goto destroy_tx_hook;

	err = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_rx_xmit,
			      conf->veth_rx_ifindex, BPF_TC_EGRESS,
			      error);
	if (err != 0)
		goto detach_rx;

	err = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_tx,
			      conf->veth_tx_ifindex, BPF_TC_EGRESS,
			      error);
	if (err != 0)
		goto detach_rx_xmit;

	err = bbdd_bpf_sockets_open(&bpf->sockets, error);
	if (err != 0)
		goto detach_tx;

	err = bbdd_bpf_sockets_attach(bpf, error);
	if (err != 0)
		goto sockets_close;

	err = bbdd_bpf_sk_lookup_attach(bpf, error);
	if (err != 0)
		goto sockets_detach;

	return bpf;

sockets_detach:
	bbdd_bpf_sockets_detach(bpf);
sockets_close:
	bbdd_bpf_sockets_close(&bpf->sockets);
detach_tx:
	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_tx,
			conf->veth_tx_ifindex, BPF_TC_EGRESS);
detach_rx_xmit:
	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_rx_xmit,
			conf->veth_rx_ifindex, BPF_TC_EGRESS);
detach_rx:
	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_rx,
			conf->veth_rx_ifindex, BPF_TC_INGRESS);
destroy_tx_hook:
	bbdd_bpf_hook_destroy(conf->veth_tx_ifindex);
destroy_rx_hook:
	bbdd_bpf_hook_destroy(conf->veth_rx_ifindex);
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
	bbdd_bpf_sk_lookup_detach(bpf);
	bbdd_bpf_sockets_detach(bpf);
	bbdd_bpf_sockets_close(&bpf->sockets);

	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_tx,
			bpf->conf.veth_tx_ifindex, BPF_TC_EGRESS);
	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_rx_xmit,
			bpf->conf.veth_rx_ifindex, BPF_TC_EGRESS);
	bbdd_bpf_detach(bpf->skel->progs.bbdd_xmit_veth_rx,
			bpf->conf.veth_rx_ifindex, BPF_TC_INGRESS);

	bbdd_bpf_hook_destroy(bpf->conf.veth_tx_ifindex);
	bbdd_bpf_hook_destroy(bpf->conf.veth_rx_ifindex);

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
	rc = bbdd_jrpc_append_uint64(obj, name, value);
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

#define FIELD(NAME) {							\
		uint64_t value = stats->NAME + bpf->diag_stats.NAME;	\
		if (bbdd_bpf_add_stat(obj, #NAME, value, error))	\
			goto err;					\
	}

	BBDD_PROG_GLOBAL_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

static int bbdd_bpf_sess_data_lookup(struct bbdd_bpf *bpf,
				     uint32_t discr,
				     struct bbdd_prog_session_data *data,
				     char **error)
{
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_prog_session_data_hash,
				   &discr, sizeof(discr),
				   data, sizeof(*data), 0);
	if (err != 0)
		bbdd_util_fmterr(error,
				 "Failed to look up BPF session data for discr %u: %s",
				 discr, strerror(-err));

	return err;
}

struct json_object *bbdd_bpf_session_diag_stats_json(struct bbdd_bpf *bpf,
						     uint32_t discr,
						     char **error)
{
	struct bbdd_prog_session_data data;
	struct bbdd_bpf_session *bsess;
	struct json_object *obj;
	int err;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "No BPF session found for discr %u",
				 discr);
		return NULL;
	}

	err = bbdd_bpf_sess_data_lookup(bpf, discr, &data, error);
	if (err)
		return NULL;

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME) {							\
		uint64_t value = data.diag_stats.NAME +			\
				 bsess->diag_stats.NAME;		\
		if (bbdd_bpf_add_stat(obj, #NAME, value, error))	\
			goto err;					\
	}

	BBDD_PROG_SESSION_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_bpf_session_stats_json(struct bbdd_bpf *bpf,
						uint32_t discr,
						char **error)
{
	struct bbdd_prog_session_data data;
	struct bbdd_bpf_session *bsess;
	struct json_object *obj;
	int err;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "No BPF session found for discr %u",
				 discr);
		return NULL;
	}

	err = bbdd_bpf_sess_data_lookup(bpf, discr, &data, error);
	if (err)
		return NULL;

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME) {							\
		uint64_t value = data.stats.NAME + bsess->stats.NAME;	\
		if (bbdd_bpf_add_stat(obj, #NAME, value, error))	\
			goto err;					\
	}

	BBDD_PROG_SESSION_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

static const char *bbdd_bpf_session_state_str(enum bbdd_bpf_session_state bstate)
{
	switch (bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:         return "stable";
	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:    return "await_final";
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL: return "await_non_final";
	}
	return "unknown";
}

static struct json_object *
bbdd_bpf_timing_json(const struct bbdd_d_session_data_timing *timing)
{
	struct json_object *obj = json_object_new_object();

	if (obj == NULL)
		return NULL;
	if (bbdd_jrpc_append_int(obj, "detect_mult", timing->detect_mult) != 0 ||
	    bbdd_jrpc_append_int(obj, "min_tx_us", timing->min_tx_us) != 0 ||
	    bbdd_jrpc_append_int(obj, "min_rx_us", timing->min_rx_us) != 0) {
		json_object_put(obj);
		return NULL;
	}
	return obj;
}

int bbdd_bpf_session_state_json(struct bbdd_bpf *bpf, uint32_t discr,
				struct json_object *state_obj, char **error)
{
	struct bbdd_bpf_session *bsess;
	struct json_object *timing_obj;
	struct json_object *bpf_obj;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "No BPF session found for discr %u",
				 discr);
		return -1;
	}

	bpf_obj = json_object_new_object();
	if (bpf_obj == NULL)
		goto put_bpf_obj;

	if (bbdd_jrpc_append_str(bpf_obj, "bstate",
				 bbdd_bpf_session_state_str(bsess->bstate)) != 0)
		goto put_bpf_obj;

	timing_obj = bbdd_bpf_timing_json(&bsess->eff_timing);
	if (timing_obj == NULL)
		goto put_bpf_obj;

	if (bbdd_jrpc_append_obj(bpf_obj, "eff_timing", &timing_obj) != 0)
		goto put_timing_obj;

	switch (bsess->bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		break;
	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		timing_obj = bbdd_bpf_timing_json(&bsess->poll_timing);
		if (timing_obj == NULL)
			goto put_bpf_obj;
		if (bbdd_jrpc_append_obj(bpf_obj, "poll_timing",
					 &timing_obj) != 0)
			goto put_timing_obj;
		if (bsess->qd_timing != NULL &&
		    bbdd_jrpc_append_bool(bpf_obj, "qd_timing", true) != 0)
			goto put_bpf_obj;
		break;
	}

	if (bbdd_jrpc_append_obj(state_obj, "bpf", &bpf_obj) != 0)
		goto put_bpf_obj;

	return 0;

put_timing_obj:
	json_object_put(timing_obj);
put_bpf_obj:
	json_object_put(bpf_obj);
	bbdd_util_fmterr(error, "%m");
	return -1;
}

int bbdd_bpf_session_stats_fill(struct bbdd_bpf *bpf, uint32_t discr,
				struct bbdd_prog_session_data_stats *out,
				char **error)
{
	struct bbdd_prog_session_data data;
	struct bbdd_bpf_session *bsess;
	int err;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "No BPF session found for discr %u",
				 discr);
		return -1;
	}

	err = bbdd_bpf_sess_data_lookup(bpf, discr, &data, error);
	if (err)
		return -1;

#define FIELD(NAME)						\
		out->NAME = data.stats.NAME + bsess->stats.NAME;
	BBDD_PROG_SESSION_STATS(FIELD)
#undef FIELD

	return 0;
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

int bbdd_bpf_session_add(struct bbdd_bpf *bpf,
			 const struct bbdd_d_session *dsess,
			 char **error)
{
	struct bbdd_bpf_session *bsess;
	int sock_fd;
	int err;

	bsess = malloc(sizeof(*bsess));
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "%m");
		return -1;
	}

	sock_fd = bbdd_d_session_open_sock(dsess, bpf->conf.veth_tx_ifindex,
					   error);
	if (sock_fd < 0) {
		err = sock_fd;
		goto free_bsess;
	}

	*bsess = (struct bbdd_bpf_session) {
		.discr = dsess->local.discr,
		.gen_id = 0,
		.sock_fd = sock_fd,

		.bstate = BBDD_BPF_SESSION_STATE_STABLE,
		.eff_timing = dsess->local.timing,
		.qd_timing = NULL,
	};

	err = __bbdd_bpf_session_update(bpf, dsess, bsess, true, error);
	if (err != 0)
		goto close_sock;

	HASH_ADD_INT(bpf->sdir, discr, bsess);
	return 0;

close_sock:
	close(sock_fd);
free_bsess:
	free(bsess);
	return -1;
}

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    const struct bbdd_d_session *dsess,
			    char **error)
{
	struct bbdd_d_session_data_timing *timing;
	uint32_t discr = dsess->local.discr;
	struct bbdd_bpf_session *bsess;
	bool need_poll = false;
	bool apply_imm = true;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL) {
		bbdd_util_fmterr(error, "No BPF session found for discr %u",
				 discr);
		return -1;
	}

	/* Below, we want to compare w/ the last poll sequence, if any. */
	switch (bsess->bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		timing = &bsess->eff_timing;
		break;
	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		timing = &bsess->poll_timing;
		break;
	}

	/* If either DesiredMinTxInterval is changed or RequiredMinRxInterval is
	 * changed, a Poll Sequence MUST be initiated. */
	if (dsess->local.timing.min_tx_us != timing->min_tx_us ||
	    dsess->local.timing.min_rx_us != timing->min_rx_us)
		need_poll = true;

	/* If bfd.DesiredMinTxInterval is increased and bfd.SessionState is Up,
	 * the actual transmission interval used MUST NOT change until the Poll
	 * Sequence has terminated. */
	if (dsess->local.state.state == BBDD_BFD_PKT_STATE_UP &&
	    dsess->local.timing.min_tx_us > timing->min_tx_us)
		apply_imm = false;

	/* If bfd.RequiredMinRxInterval is reduced and bfd.SessionState is Up,
	 * the previous value of bfd.RequiredMinRxInterval MUST be used when
	 * calculating the Detection Time for the remote system until the Poll
	 * Sequence has terminated. */
	if (dsess->local.state.state == BBDD_BFD_PKT_STATE_UP &&
	    dsess->local.timing.min_rx_us < timing->min_rx_us)
		apply_imm = false;

	switch (bsess->bstate) {
	case BBDD_BPF_SESSION_STATE_STABLE:
		if (apply_imm)
			bsess->eff_timing = dsess->local.timing;
		if (need_poll) {
			bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: change, await final",
					    dsess->local.discr);
			bsess->poll_timing = dsess->local.timing;
			bsess->bstate = BBDD_BPF_SESSION_STATE_AWAIT_FINAL;
		}
		break;

	case BBDD_BPF_SESSION_STATE_AWAIT_FINAL:
	case BBDD_BPF_SESSION_STATE_AWAIT_NON_FINAL:
		/* We are already polling, just set the mark and don't touch any
		 * configuration. */
		if (need_poll) {
			bbdd_mon_send_debug(bpf->rb_ctx->mon, "session discr %u: change, queue timing",
					    dsess->local.discr);
			bsess->qd_timing = &dsess->local.timing;
		}
		break;
	}

	return __bbdd_bpf_session_update(bpf, dsess, bsess, false, error);
}

void bbdd_bpf_session_del(struct bbdd_bpf *bpf,
			  const struct bbdd_d_session *dsess)
{
	uint32_t discr = dsess->local.discr;
	struct bbdd_bpf_session *bsess;

	bsess = bbdd_bpf_sdir_get_session(bpf, discr);
	if (bsess == NULL)
		return;

	HASH_DEL(bpf->sdir, bsess);

	/* The packet will be dropped by the looper when no matching session is
	 * found. */
	bbdd_bpf_session_conf_delete(bpf, bsess->discr);

	close(bsess->sock_fd);
	free(bsess);
}
