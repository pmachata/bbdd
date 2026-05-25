// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-bfdd.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>

#include "bbdd.h"
#include "bbdd-c.h"
#include "bbdd-d.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-poll.h"
#include "bbdd-prog-stat.h"
#include "bbdd-util.h"
#include "bfddp.h"

struct bbdd_bfdd {
	struct bfddp_ctx *bctx;
	int fd;
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;

	struct bbdd_bfdd_cbs cbs;
};

static int bbdd_bfdd_handle_messages(struct bbdd_bfdd *bfdd, char **error)
{
	struct bfddp_message *msg;
	int rc;

	do {
		msg = bfddp_next_message(bfdd->bctx);
		if (msg == NULL)
			break;

		rc = bfdd->cbs.message_cb(bfdd, msg, bfdd->cbs.sock_cb_data,
					  error);
		if (rc < 0)
			return rc;
	} while (msg != NULL);

	bfddp_read_finish(bfdd->bctx);
	return 0;
}

static int bbdd_bfdd_poll_unset(struct bbdd_bfdd *bfdd)
{
	int rc;

	if (bfdd->fd >= 0) {
		rc = bbdd_poll_unset_fd(bfdd->pctx, bfdd->fd);
		if (rc < 0)
			return rc;
		bfdd->fd = -1;
	}
	return 0;
}

static int bbdd_bfdd_fmterr_errno(char **error)
{
	if (errno == 0)
		*error = NULL;
	else
		bbdd_util_fmterr(error, "%m");
	return -1;
}

static int bbdd_bfdd_read_event(struct bbdd_bfdd *bfdd, char **error)
{
	ssize_t rv;

	rv = bfddp_read(bfdd->bctx);
	if (rv == -1)
		return bbdd_bfdd_fmterr_errno(error);

	if (rv > 0)
		bbdd_mon_send_debug(bfdd->mon, "bfdd: received %zd bytes", rv);

	return bbdd_bfdd_handle_messages(bfdd, error);
}

static int bbdd_bfdd_write_event(struct bbdd_bfdd *bfdd, char **error)
{
	ssize_t rv;

	rv = bfddp_write(bfdd->bctx);
	if (rv == -1)
		return bbdd_bfdd_fmterr_errno(error);

	if (rv > 0)
		bbdd_mon_send_debug(bfdd->mon, "bfdd: sent %zd bytes", rv);

	return 0;
}

static int bbdd_bfdd_event(struct bbdd_poll_ctx *pctx, short revents,
			   void *data, char **)
{
	struct bbdd_bfdd *bfdd = data;
	short events = POLLIN | POLLHUP;
	char *error;
	int rc;

	if (revents & POLLHUP) {
		/* Like for the error case, unset FD because the callback
		 * doesn't have to. */
		bbdd_bfdd_poll_unset(bfdd);

		assert(bfdd->cbs.hangup_cb != NULL);
		bfdd->cbs.hangup_cb(bfdd, bfdd->cbs.sock_cb_data);
		return 0;
	}

	if (revents & POLLIN) {
		rc = bbdd_bfdd_read_event(bfdd, &error);
		if (rc < 0)
			goto error;
	}

	if (revents & POLLOUT) {
		rc = bbdd_bfdd_write_event(bfdd, &error);
		if (rc < 0)
			goto error;
	}

	if (bfddp_write_pending(bfdd->bctx))
		events |= POLLOUT;

	rc = bbdd_poll_set_fd(pctx, bfdd->fd, events,
			      bbdd_bfdd_event, bfdd, &error);
	if (rc < 0) {
		bbdd_util_printerr(&error, "Failed to reset BFD poll FD");
		goto error;
	}

	return 0;

error:
	/* The sockerr callback below could call bbdd_bfdd_close(). But doesn't
	 * have to, so unset the poll FD now. */
	bbdd_bfdd_poll_unset(bfdd);

	bfdd->cbs.sockerr_cb(bfdd, error, bfdd->cbs.sock_cb_data);
	free(error);

	return 0;
}

static int bbdd_bfdd_connected(struct bbdd_poll_ctx *pctx, short,
			       void *data, char **)
{
	struct bbdd_bfdd *bfdd = data;
	char *error;
	int rv;

	rv = bfddp_is_connected(bfdd->bctx);
	if (rv == 1)
		/* bfddp_is_connected() returns `1` if still not connected. Just
		 * keep the same event handler and wait for more. */
		return 0;

	if (rv == -1) {
		bbdd_util_fmterr(&error, "Error connecting to the BFD DP socket");
		goto error;
	}

	rv = bbdd_poll_set_fd(pctx, bfdd->fd, POLLIN | POLLHUP,
			      bbdd_bfdd_event, bfdd, &error);
	if (rv < 0)
		goto error;

	bfdd->cbs.connected_cb(bfdd, bfdd->cbs.conn_cb_data);
	return 0;

error:
	/* The callback could call bbdd_bfdd_close(). But doesn't have to, so
	 * unset the poll FD now. */
	bbdd_bfdd_poll_unset(bfdd);
	bfdd->cbs.connect_failed_cb(bfdd, &error, bfdd->cbs.conn_cb_data);

	/* Keep any errors that we encountered here to ourselves, the daemon
	 * should stay up and running. */
	return 0;
}

struct bbdd_bfdd *bbdd_bfdd_open(const char *path,
				 struct bbdd_poll_ctx *pctx,
				 struct bbdd_mon *mon,
				 const struct bbdd_bfdd_cbs *cbs,
				 char **error)
{
	struct bbdd_sockaddr sa;
	struct bfddp_ctx *bctx;
	struct bbdd_bfdd *bfdd;
	int rc;
	int fd;

	rc = bbdd_sock_parse_addrstr(AF_UNIX, path, &sa, error);
	if (rc < 0)
		return NULL;

	bctx = bfddp_new(4096, 4096);
	if (bctx == NULL) {
		bbdd_util_fmterr(error, "Failed to open libbfd context");
		return NULL;
	}

	rc = bfddp_connect(bctx, &sa.sa, sa.len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to connect to bfd datapath socket");
		goto free_bfddp;
	}

	fd = bfddp_get_fd(bctx);
	if (fd < 0) {
		/* This shouldn't happen. */
		bbdd_util_fmterr(error, "libbfd socket closed");
		goto free_bfddp;
	}

	bfdd = malloc(sizeof(*bfdd));
	if (bfdd == NULL) {
		bbdd_util_fmterr(error, "%m");
		goto free_bfddp;
	}
	*bfdd = (struct bbdd_bfdd) {
		.bctx = bctx,
		.fd = fd,
		.pctx = pctx,
		.mon = mon,
		.cbs = *cbs,
	};

	rc = bbdd_poll_set_fd(pctx, fd, POLLOUT,
			      bbdd_bfdd_connected, bfdd,
			      error);
	if (rc < 0)
		goto free_bfdd;

	return bfdd;

free_bfdd:
	free(bfdd);
free_bfddp:
	bfddp_free(bctx);
	return NULL;
}

struct bbdd_bfdd *bbdd_bfdd_open_client(int fd,
					struct bbdd_poll_ctx *pctx,
					struct bbdd_mon *mon,
					const struct bbdd_bfdd_cbs *cbs,
					char **error)
{
	struct bfddp_ctx *bctx;
	struct bbdd_bfdd *bfdd;
	int rc;

	bctx = bfddp_new(4096, 4096);
	if (bctx == NULL) {
		bbdd_util_fmterr(error, "Failed to open libbfd context");
		return NULL;
	}

	bfddp_set_fd(bctx, fd);

	bfdd = malloc(sizeof(*bfdd));
	if (bfdd == NULL) {
		bbdd_util_fmterr(error, "%m");
		goto free_bfddp;
	}
	*bfdd = (struct bbdd_bfdd) {
		.bctx = bctx,
		.fd = fd,
		.pctx = pctx,
		.mon = mon,
		.cbs = *cbs,
	};

	rc = bbdd_poll_set_fd(pctx, bfdd->fd, POLLIN | POLLHUP,
			      bbdd_bfdd_event, bfdd, error);
	if (rc < 0)
		goto free_bfdd;

	return bfdd;

free_bfdd:
	free(bfdd);
free_bfddp:
	bfddp_free(bctx);
	return NULL;
}

bool bbdd_bfdd_is_connected(const struct bbdd_bfdd *bfdd)
{
	return bfddp_is_connected(bfdd->bctx) == 0;
}

static int bbdd_bfdd_write_enqueue(struct bbdd_bfdd *bfdd,
				   const struct bfddp_message *msg,
				   char **error)
{
	size_t written;
	int rc;

	rc = bbdd_poll_set_fd(bfdd->pctx, bfdd->fd, POLLIN | POLLOUT | POLLHUP,
			      bbdd_bfdd_event, bfdd, error);
	if (rc != 0)
		return rc;

	/* returns 0 on full buffer or the number of bytes buffered. */
	written = bfddp_write_enqueue(bfdd->bctx, msg);
	if (written == 0) {
		bbdd_util_fmterr(error, "bfdd: Buffer full");
		return -1;
	}

	return 0;
}

int bbdd_bfdd_reply_counters(struct bbdd_bfdd *bfdd,
			     uint16_t msg_id, uint32_t discr,
			     const struct bbdd_prog_session_data_stats *stats,
			     char **error)
{
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(BFD_SESSION_COUNTERS),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.session_counters)),

		.data.session_counters = {
			.lid = bbdd_hton32(discr),
			.control_input_bytes = bbdd_hton64(stats->rx_bytes),
			.control_input_packets = bbdd_hton64(stats->rx_packets),
			.control_output_bytes = bbdd_hton64(stats->tx_bytes),
			.control_output_packets = bbdd_hton64(stats->tx_packets),
			/* echo counters are zero */
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_reply_echo(struct bbdd_bfdd *bfdd,
			 uint16_t msg_id,
			 const struct bfddp_echo *in_echo, char **error)
{
	uint64_t dp_time = bbdd_util_now();
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(ECHO_REPLY),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.echo)),

		.data.echo = (struct bfddp_echo) {
			.dp_time = bbdd_hton64(dp_time),
			.bfdd_time = in_echo->bfdd_time,
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_send_echo(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			uint64_t dp_time_us, char **error)
{
	struct bfddp_message msg = {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(ECHO_REQUEST),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.echo)),
		.data.echo = {
			.dp_time = bbdd_hton64(dp_time_us),
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

static int bbdd_bfdd_session_d_from_c(struct bbdd_nl *nl,
				      const struct bbdd_c_session *csess,
				      struct bbdd_d_session *dsess,
				      char **error)
{
	int rc;

	/* Most either default to 0 or are required.
	 *
	 * For the TTL: "the TTL [...] MUST be [...] checked to be equal to the
	 * maximum value on reception", so it makes sense to default to 255.
	 */
	*dsess = (struct bbdd_d_session){
		.ttl = 255,
	};

	rc = bbdd_d_session_apply_c(dsess, csess, nl, NULL, error);
	if (rc != 0)
		return -EINVAL;

	return 0;
}

static int bbdd_bfdd_msg_fill_netif(int ifindex, char *buf, char **error)
{
	if (ifindex == 0)
		return 0;
	if (if_indextoname(ifindex, buf) != NULL)
		return 0;

	bbdd_util_fmterr(error, "Could not translate ifindex %d to interface name: %m",
			 ifindex);
	return -EINVAL;
}

int bbdd_bfdd_send_state_change(struct bbdd_bfdd *bfdd,
				const struct bbdd_d_session *dsess,
				char **error)
{
	uint32_t remote_flags = 0;

	if (dsess->remote.flags.cpi)
		remote_flags |= RBIT_CPI;

	struct bfddp_message msg = {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(BFD_STATE_CHANGE),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.state)),

		.data.state = {
			.lid = bbdd_hton32(dsess->local.discr),
			.rid = bbdd_hton32(dsess->remote.discr),
			.remote_flags = bbdd_hton32(remote_flags),
			.desired_tx = bbdd_hton32(dsess->remote.timing.min_tx_us),
			.required_rx = bbdd_hton32(dsess->remote.timing.min_rx_us),
			.state = dsess->remote.state.state,
			.diagnostics = dsess->remote.state.diag,
			.detection_multiplier = dsess->remote.timing.detect_mult,
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_add_session(struct bbdd_bfdd *bfdd,
			  struct bbdd_nl *nl,
			  const struct bbdd_c_session *csess,
			  uint16_t msg_id, char **error)
{
	struct bbdd_d_session dsess;
	struct bfddp_message msg = {};
	struct in6_addr src = {};
	struct in6_addr dst;
	const void *buf;
	size_t bufsz;
	uint32_t flags = 0;
	uint16_t length;
	int rc;

	rc = bbdd_bfdd_session_d_from_c(nl, csess, &dsess, error);
	if (rc != 0)
		return rc;

	length = dsess.vrf_table != 0
		    ? (sizeof(msg.header) + sizeof(msg.data.session_cumulus))
		    : (sizeof(msg.header) + sizeof(msg.data.session));

	if (dsess.dst.sa.sa_family == AF_INET6)
		flags |= SESSION_IPV6;
	if (dsess.local.flags.multihop)
		flags |= SESSION_MULTIHOP;
	if (dsess.local.flags.cpi)
		flags |= SESSION_CBIT;
	if (dsess.local.flags.passive)
		flags |= SESSION_PASSIVE;
	if (dsess.local.flags.shutdown)
		flags |= SESSION_SHUTDOWN;

	if (dsess.src.sa.sa_family != 0) {
		buf = bbdd_sockaddr_addrbuf(&dsess.src, &bufsz, error);
		if (buf == NULL)
			return -EPROTO;
		memcpy(&src, buf, bufsz);
	}

	assert(dsess.dst.sa.sa_family != 0);
	buf = bbdd_sockaddr_addrbuf(&dsess.dst, &bufsz, error);
	if (buf == NULL)
		return -EPROTO;
	memcpy(&dst, buf, bufsz);

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(DP_ADD_SESSION),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(length),

		.data.session_cumulus = {
			.session = {
				.flags = bbdd_hton32(flags),
				.src = src,
				.dst = dst,
				.lid = bbdd_hton32(dsess.local.discr),
				.min_tx = bbdd_hton32(dsess.local.timing.min_tx_us),
				.min_rx = bbdd_hton32(dsess.local.timing.min_rx_us),
				/* Wire hold_time is in milliseconds. */
				.hold_time = bbdd_hton32(dsess.hold_time_us / 1000),
				.ttl = dsess.ttl,
				.detect_mult = dsess.local.timing.detect_mult,
				.ifindex = bbdd_hton32(dsess.ifindex),
			},
			.vrf_id = bbdd_hton32(dsess.vrf_table),
		},
	};

	rc = bbdd_bfdd_msg_fill_netif(dsess.vrf_ifindex,
				      msg.data.session_cumulus.vrfname, error);
	if (rc != 0)
		return rc;

	rc = bbdd_bfdd_msg_fill_netif(dsess.ifindex,
				      msg.data.session.ifname, error);
	if (rc != 0)
		return rc;

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_del_session(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			  uint32_t discr, char **error)
{
	struct bfddp_message msg = {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(DP_DELETE_SESSION),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.session)),

		.data.session.lid = bbdd_hton32(discr),
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_request_counters(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			       uint32_t discr, char **error)
{
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(DP_REQUEST_SESSION_COUNTERS),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.counters_req)),

		.data.counters_req = {
			.lid = bbdd_hton32(discr),
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

void bbdd_bfdd_close(struct bbdd_bfdd *bfdd)
{
	bbdd_bfdd_poll_unset(bfdd);
	bfddp_free(bfdd->bctx);
	if (bfdd->cbs.connect_free_cb != NULL)
		bfdd->cbs.connect_free_cb(bfdd->cbs.conn_cb_data);
	if (bfdd->cbs.sock_free_cb != NULL)
		bfdd->cbs.sock_free_cb(bfdd->cbs.sock_cb_data);
	free(bfdd);
}

static int bbdd_bfdd_session_to_c_addr(struct bbdd_c_session_addr *to,
				       const struct in6_addr *from,
				       int af, char **error)
{
	const char *ret;

	ret = inet_ntop(af, from, to->str, sizeof(to->str));
	if (ret == NULL) {
		bbdd_util_fmterr(error, "Failed to convert address: %m");
		return -1;
	}

	to->af = af;
	return 0;
}

static int bbdd_bfdd_session_to_c(const struct bfddp_session_cumulus *cmsess,
				  struct bbdd_c_session *csess,
				  char **error)
{
	const struct bfddp_session *fsess = &cmsess->session;
	uint32_t flags = bbdd_ntoh32(fsess->flags);
	int af = (flags & SESSION_IPV6) ? AF_INET6 : AF_INET;
	size_t addr_sz = (flags & SESSION_IPV6) ? 16 : 4;
	unsigned char zeroes[16] = {};
	int rc;

	if (flags & SESSION_ECHO) {
		bbdd_util_fmterr(error, "Echo not supported");
		return -1;
	}

	if (flags & SESSION_DEMAND) {
		bbdd_util_fmterr(error, "Demand mode not supported");
		return -1;
	}

	memset(csess, 0, sizeof(*csess));

#define SET_FLAG(name, FLAG) do {					\
		csess->flags.name.seen = true;				\
		csess->flags.name.value = !!(flags & (FLAG));		\
	} while (0)
	SET_FLAG(multihop, SESSION_MULTIHOP);
	SET_FLAG(cpi,      SESSION_CBIT);
	SET_FLAG(passive,  SESSION_PASSIVE);
	SET_FLAG(shutdown, SESSION_SHUTDOWN);
#undef SET_FLAG

	/* Source address is not mandatory. */
	if (memcmp(&fsess->src, zeroes, addr_sz) == 0) {
		csess->src.unset = true;
	} else {
		rc = bbdd_bfdd_session_to_c_addr(&csess->src, &fsess->src,
						 af, error);
		if (rc != 0)
			return rc;
	}

	rc = bbdd_bfdd_session_to_c_addr(&csess->dst, &fsess->dst, af, error);
	if (rc != 0)
		return rc;

	csess->discr = bbdd_ntoh32(fsess->lid);
	csess->discr_seen = (csess->discr != 0);

	csess->min_tx_us = bbdd_ntoh32(fsess->min_tx);
	csess->min_tx_us_seen = 1;

	csess->min_rx_us = bbdd_ntoh32(fsess->min_rx);
	csess->min_rx_us_seen = 1;

	/* Wire hold_time is in milliseconds; we store microseconds. The
	 * conversion can overflow uint32_t for values above ~4M ms (~71
	 * minutes). Such values make no operational sense for BFD, so saturate
	 * at UINT32_MAX rather than wrapping silently. */
	{
		uint32_t hold_time_ms = bbdd_ntoh32(fsess->hold_time);

		if (hold_time_ms > UINT32_MAX / 1000) {
			fprintf(stderr,
				"bfdd: hold_time %u ms overflows uint32_t, saturating\n",
				hold_time_ms);
			csess->hold_time_us = UINT32_MAX;
		} else {
			csess->hold_time_us = hold_time_ms * 1000;
		}
	}
	csess->hold_time_us_seen = 1;

	csess->ttl = fsess->ttl;
	csess->ttl_seen = 1;

	csess->detect_mult = fsess->detect_mult;
	csess->detect_mult_seen = 1;

	if (bbdd_ntoh32(fsess->ifindex) == 0) {
		csess->netif.unset = true;
	} else {
		csess->netif.ifindex = bbdd_ntoh32(fsess->ifindex);
		csess->netif.ifindex_seen = 1;

		if (fsess->ifname[0] != '\0') {
			/* If an interface name is too long, it will be truncated,
			 * and will subsequently fail validation. So we don't care,
			 * and this contraption silences a GCC warning. */
			(void) (snprintf(csess->netif.name,
					 sizeof(csess->netif.name),
					 "%s", fsess->ifname) != 0);
			csess->netif.name_seen = 1;
		}
	}

	if (bbdd_ntoh32(cmsess->vrf_id) == 0) {
		csess->vrf.netif.unset = true;
	} else {
		csess->vrf.table = bbdd_ntoh32(cmsess->vrf_id);
		csess->vrf.table_seen = 1;

		if (cmsess->vrfname[0] != '\0') {
			(void) (snprintf(csess->vrf.netif.name,
					 sizeof(csess->vrf.netif.name),
					 "%s", cmsess->vrfname) != 0);
			csess->vrf.netif.name_seen = 1;
		}
	}

	return 0;
}

int bbdd_bfdd_session_msg_to_c(const struct bfddp_message *msg,
			       struct bbdd_c_session *csess,
			       char **error)
{
	enum {
		std_len = (sizeof(msg->header) +
			   sizeof(msg->data.session)),
		cml_len = (sizeof(msg->header) +
			   sizeof(msg->data.session_cumulus)),
	};
	uint16_t length = bbdd_ntoh16(msg->header.length);
	enum bfddp_message_type bmt;

	bmt = bbdd_ntoh16(msg->header.type);
	assert(bmt == DP_ADD_SESSION);

	switch (length) {
		struct bfddp_session_cumulus session_cumulus;

	case std_len:
		session_cumulus = (struct bfddp_session_cumulus) {
			.session = msg->data.session,
		};
		return bbdd_bfdd_session_to_c(&session_cumulus, csess, error);

	case cml_len:
		return bbdd_bfdd_session_to_c(&msg->data.session_cumulus,
					      csess, error);
	}

	bbdd_util_fmterr(error, "DP_ADD_SESSION: Invalid length: got %u, expected %u or %u",
			 length, std_len, cml_len);
	return -EMSGSIZE;
}

static int bbdd_bfdd_format_add_session(const struct bfddp_message *msg,
					struct bbdd_mon_message *mon_msg,
					char **error)
{
	struct bbdd_c_session csess = {};
	struct json_object *params = NULL;
	struct json_object *sess_obj = NULL;
	int rc;

	rc = bbdd_bfdd_session_msg_to_c(msg, &csess, error);
	if (rc != 0)
		return -1;

	params = json_object_new_object();
	if (params == NULL)
		goto err;

	sess_obj = bbdd_c_jrpc_session_obj(&csess);
	if (sess_obj == NULL)
		goto put_params;

	if (bbdd_jrpc_append_obj(params, "session", &sess_obj) != 0)
		goto put_sess_obj;

	*mon_msg = (struct bbdd_mon_message) {
		.method = "bfdd:sess-add",
		.params = params,
	};
	return 0;

put_sess_obj:
	json_object_put(sess_obj);
put_params:
	json_object_put(params);
err:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

int bbdd_bfdd_format_state_change(const struct bfddp_state_change *sc,
				  const char *method,
				  struct bbdd_mon_message *mon_msg,
				  char **error)
{
	struct json_object *params;
	struct json_object *sess_obj;
	struct json_object *state_obj;
	struct json_object *data_obj;
	struct json_object *remote_obj;

	params = json_object_new_object();
	if (params == NULL)
		goto err;

	sess_obj = json_object_new_object();
	if (sess_obj == NULL)
		goto put_params;

	data_obj = json_object_new_object();
	if (data_obj == NULL)
		goto put_sess_obj;

	state_obj = json_object_new_object();
	if (state_obj == NULL)
		goto put_data_obj;

	remote_obj = json_object_new_object();
	if (remote_obj == NULL)
		goto put_state_obj;

	if (bbdd_jrpc_append_str(remote_obj, "state",
				 bbdd_d_bfd_state_to_str(sc->state)) != 0 ||
	    bbdd_jrpc_append_str(remote_obj, "diag",
				 bbdd_d_bfd_diag_to_str(sc->diagnostics)) != 0 ||
	    bbdd_jrpc_append_int(remote_obj, "discr",
				 bbdd_ntoh32(sc->rid)) != 0 ||
	    bbdd_jrpc_append_int(remote_obj, "detect_mult",
				 sc->detection_multiplier) != 0 ||
	    bbdd_jrpc_append_int(remote_obj, "min_tx_us",
				 bbdd_ntoh32(sc->desired_tx)) != 0 ||
	    bbdd_jrpc_append_int(remote_obj, "min_rx_us",
				 bbdd_ntoh32(sc->required_rx)) != 0 ||

	    bbdd_jrpc_append_obj(state_obj, "remote", &remote_obj) != 0)
		goto put_remote_obj;

	if (bbdd_jrpc_append_obj(sess_obj, "state", &state_obj) != 0)
		goto put_state_obj;

	if (bbdd_jrpc_append_int(data_obj, "discr", bbdd_ntoh32(sc->lid)) != 0 ||
	    bbdd_jrpc_append_obj(sess_obj, "data", &data_obj) != 0)
		goto put_data_obj;

	if (bbdd_jrpc_append_obj(params, "session", &sess_obj) != 0)
		goto put_sess_obj;

	*mon_msg = (struct bbdd_mon_message) {
		.method = method,
		.params = params,
	};
	return 0;

put_remote_obj:
	json_object_put(remote_obj);
put_state_obj:
	json_object_put(state_obj);
put_data_obj:
	json_object_put(data_obj);
put_sess_obj:
	json_object_put(sess_obj);
put_params:
	json_object_put(params);
err:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

static int bbdd_bfdd_format_lid_msg(uint32_t lid, const char *method,
				    struct bbdd_mon_message *mon_msg,
				    char **error)
{
	struct json_object *params;

	params = json_object_new_object();
	if (params == NULL)
		goto err;

	if (bbdd_jrpc_append_int(params, "lid", lid) != 0)
		goto put_params;

	*mon_msg = (struct bbdd_mon_message) {
		.method = method,
		.params = params,
	};
	return 0;

put_params:
	json_object_put(params);
err:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

static int
bbdd_bfdd_format_echo(const struct bfddp_echo *echo, const char *method,
		      struct bbdd_mon_message *mon_msg, char **error)
{
	struct json_object *params;

	params = json_object_new_object();
	if (params == NULL)
		goto err;

	if (bbdd_jrpc_append_uint64(params, "dp-time",
				    bbdd_ntoh64(echo->dp_time)) ||
	    bbdd_jrpc_append_uint64(params, "bfdd-time",
				    bbdd_ntoh64(echo->bfdd_time)))
		goto put_params;

	*mon_msg = (struct bbdd_mon_message) {
		.method = method,
		.params = params,
	};
	return 0;

put_params:
	json_object_put(params);
err:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

static int
bbdd_bfdd_msg_format_bare(const char *method, struct bbdd_mon_message *mon_msg)
{
	*mon_msg = (struct bbdd_mon_message) {
		.method = method,
	};
	return 0;
}

static int
bbdd_bfdd_format_unknown(enum bfddp_message_type bmt,
			 struct bbdd_mon_message *mon_msg, char **error)
{
	struct json_object *params;

	params = json_object_new_object();
	if (params == NULL)
		goto err;

	if (bbdd_jrpc_append_int(params, "type", bmt) != 0)
		goto put_params;

	*mon_msg = (struct bbdd_mon_message) {
		.method = "bfdd:unknown",
		.params = params,
	};
	return 0;

put_params:
	json_object_put(params);
err:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

int bbdd_bfdd_msg_format_mon(const struct bfddp_message *msg,
			     struct bbdd_mon_message *mon_msg, char **error)
{
	enum bfddp_message_type bmt = bbdd_ntoh16(msg->header.type);

	switch (bmt) {
		uint32_t lid;

	case DP_ADD_SESSION:
		return bbdd_bfdd_format_add_session(msg, mon_msg, error);

	case DP_DELETE_SESSION:
		lid = bbdd_ntoh32(msg->data.session.lid);
		return bbdd_bfdd_format_lid_msg(lid, "bfdd:sess-del",
						mon_msg, error);

	case DP_REQUEST_SESSION_COUNTERS:
		lid = bbdd_ntoh32(msg->data.counters_req.lid);
		return bbdd_bfdd_format_lid_msg(lid, "bfdd:sess-cnt-req",
						mon_msg, error);

	case BFD_STATE_CHANGE:
		return bbdd_bfdd_format_state_change(&msg->data.state,
						     "bfdd:state-change",
						     mon_msg, error);

	case ECHO_REQUEST:
		return bbdd_bfdd_format_echo(&msg->data.echo, "bfdd:echo-req",
					     mon_msg, error);
	case ECHO_REPLY:
		return bbdd_bfdd_format_echo(&msg->data.echo, "bfdd:echo-rep",
					     mon_msg, error);
	case BFD_SESSION_COUNTERS:
		return bbdd_bfdd_msg_format_bare("bfdd:sess-cnt-rep", mon_msg);

	default:
		return bbdd_bfdd_format_unknown(bmt, mon_msg, error);
	}
}
