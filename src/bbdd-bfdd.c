// SPDX-License-Identifier: GPL-2.0
#include "bbdd-bfdd.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>

#include <utlist.h>

#include "bbdd.h"
#include "bbdd-c.h"
#include "bbdd-d.h"
#include "bbdd-err.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-poll.h"
#include "bbdd-prog-stat.h"
#include "bbdd-sock.h"
#include "bbdd-ssk.h"
#include "bbdd-util.h"
#include "bfddp_packet.h"

/* Tracking an in-flight bfdd-echo until ECHO_REPLY arrives. */
struct bbdd_bfdd_echo_peer {
	struct bbdd_bfdd_b *bfdd_b;
	struct bbdd_ssk_peer *peer;
	struct bbdd_ssk_cbs *ssk_cbs;
	struct json_object *id;
	bool is_dp; /* true when we sent as data plane, false when as bridge */

	struct bbdd_bfdd_echo_peer *next;
	struct bbdd_bfdd_echo_peer *prev;
};

struct bbdd_bfdd_b {
	struct bbdd_util_ssk_bfddp_tkn *tkn;

	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;

	struct bbdd_bfdd_cbs cbs;
	struct bbdd_bfdd_echo_peer *echo_peers;	/* DList */
};

/* Client (data-plane) role. */
struct bbdd_bfdd_c {
	struct bbdd_bfdd_b base;
	struct bbdd_ssk_c *ssc;
};

/* Server (BFD-daemon / bridge) role. */
struct bbdd_bfdd_d {
	struct bbdd_bfdd_b base;
	struct bbdd_ssk_peer *peer;
	struct bbdd_ssk_cbs *peer_cbs;
};

static int bbdd_bfdd_msg_len_ck(const struct bfddp_message *msg,
				size_t min_payload_len, char **error)
{
	size_t msg_len;
	size_t min_len;

	msg_len = bbdd_ntoh16(msg->header.length);
	min_len = min_payload_len + sizeof msg->header;

	if (msg_len < min_len) {
		enum bfddp_message_type bmt;

		bmt = bbdd_ntoh16(msg->header.type);
		bbdd_err_fmt(error, "Message type %d has length %zd, but has to be at least %zd",
			     bmt, msg_len, min_len);
		return -1;
	}

	return 0;
}

static int bbdd_bfdd_msg_len_validate(const struct bfddp_message *msg,
				      char **error)
{
	enum bfddp_message_type bmt;

	bmt = bbdd_ntoh16(msg->header.type);
	switch (bmt) {
	case ECHO_REQUEST:
	case ECHO_REPLY:
		return bbdd_bfdd_msg_len_ck(msg, sizeof msg->data.echo, error);

	case DP_ADD_SESSION:
	case DP_DELETE_SESSION:
		/* This comes in two variants: session, or session_cumulus.
		 * Client has to dispatch on length to find out which it is. We
		 * only check if the length is at least the basic session. */
		return bbdd_bfdd_msg_len_ck(msg, sizeof msg->data.session,
					    error);

	case BFD_STATE_CHANGE:
		return bbdd_bfdd_msg_len_ck(msg, sizeof msg->data.state, error);

	case DP_REQUEST_SESSION_COUNTERS:
		return bbdd_bfdd_msg_len_ck(msg, sizeof msg->data.counters_req,
					    error);

	case BFD_SESSION_COUNTERS:
		return bbdd_bfdd_msg_len_ck(msg,
					    sizeof msg->data.session_counters,
					    error);
	}

	bbdd_err_fmt(error, "Cannot validate message of unknown type %d", bmt);
	return -1;
}

static int bbdd_bfdd_dispatch_message(struct bbdd_util_ssk_bfddp_tkn *,
				      const struct bfddp_message *msg,
				      void *data, char **error)
{
	struct bbdd_bfdd_b *bfdd_b = data;
	int rc;

	rc = bbdd_bfdd_msg_len_validate(msg, error);
	if (rc != 0)
		return rc;

	bbdd_bfdd_mon_send_i(bfdd_b->mon, msg);
	return bfdd_b->cbs.message_cb(msg, bfdd_b->cbs.data, error);
}

static void bbdd_bfdd_bfddp_tkn_destroy(struct bbdd_ssk_peer *, void *data)
{
	struct bbdd_util_ssk_bfddp_tkn *tkn = data;

	bbdd_util_ssk_bfddp_tkn_destroy(tkn);
}

static void bbdd_bfdd_peer_done_cb(struct bbdd_ssk_peer *, void *data)
{
	/* This cb is shared between C and D, so just take the common base. */
	struct bbdd_bfdd_b *bfdd_b = data;

	bfdd_b->cbs.peer_done_cb(bfdd_b->cbs.data);
}

struct bbdd_bfdd_c *bbdd_bfdd_open_c(const char *path,
				     struct bbdd_poll_ctx *pctx,
				     struct bbdd_mon *mon,
				     const struct bbdd_bfdd_cbs *cbs,
				     char **error)
{
	struct bbdd_util_ssk_bfddp_tkn *tkn;
	struct bbdd_ssk_cbs *peer_cbs;
	struct bbdd_ssk_cbs *ssk_cbs;
	struct bbdd_bfdd_c *bfdd_c;
	struct bbdd_ssk_peer *peer;
	struct bbdd_sockaddr sa;
	struct bbdd_ssk_c *ssc;
	int rc;

	rc = bbdd_sock_parse_addrstr(AF_UNIX, path, &sa, error);
	if (rc < 0)
		return NULL;

	bfdd_c = malloc(sizeof(*bfdd_c));
	if (bfdd_c == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	ssc = bbdd_ssk_open_c(pctx, &sa, mon, error);
	if (ssc == NULL)
		goto free_bfdd_c;
	peer = bbdd_ssk_c_peer(ssc);

	tkn = bbdd_util_ssk_bfddp_tkn_create(bbdd_bfdd_dispatch_message,
					     &bfdd_c->base, error);
	if (tkn == NULL)
		goto close_ssc;

	ssk_cbs = bbdd_ssk_peer_add_cbs(peer,
					bbdd_util_ssk_bfddp_tkn_rx_cb,
					bbdd_bfdd_bfddp_tkn_destroy,
					tkn, error);
	if (ssk_cbs == NULL)
		goto close_ssc;

	peer_cbs = bbdd_ssk_peer_add_cbs(peer,
					 NULL,
					 bbdd_bfdd_peer_done_cb,
					 &bfdd_c->base, error);
	if (peer_cbs == NULL)
		goto destroy_tkn;

	*bfdd_c = (struct bbdd_bfdd_c) {
		.ssc = ssc,
		.base = {
			.tkn = tkn,

			.pctx = pctx,
			.mon = mon,
			.cbs = *cbs,
		},
	};

	return bfdd_c;

destroy_tkn:
	bbdd_util_ssk_bfddp_tkn_destroy(tkn);
close_ssc:
	/* ssk_close_c fires the tokener's own done_cb, which destroys it. */
	bbdd_ssk_close_c(ssc);
free_bfdd_c:
	free(bfdd_c);
	return NULL;
}

static void bbdd_bfdd_d_peer_done_cb(struct bbdd_ssk_peer *, void *data)
{
	struct bbdd_bfdd_d *bfdd_d = data;

	bfdd_d->peer = NULL;
	bfdd_d->base.cbs.peer_done_cb(bfdd_d->base.cbs.data);
}

struct bbdd_bfdd_d *bbdd_bfdd_attach_d(struct bbdd_ssk_peer *peer,
				       struct bbdd_poll_ctx *pctx,
				       struct bbdd_mon *mon,
				       const struct bbdd_bfdd_cbs *cbs,
				       char **error)
{
	struct bbdd_util_ssk_bfddp_tkn *tkn;
	struct bbdd_ssk_cbs *peer_cbs;
	struct bbdd_ssk_cbs *ssk_cbs;
	struct bbdd_bfdd_d *bfdd_d;

	bfdd_d = malloc(sizeof(*bfdd_d));
	if (bfdd_d == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	tkn = bbdd_util_ssk_bfddp_tkn_create(bbdd_bfdd_dispatch_message,
					     &bfdd_d->base, error);
	if (tkn == NULL)
		goto free_bfdd_d;

	ssk_cbs = bbdd_ssk_peer_add_cbs(peer,
					bbdd_util_ssk_bfddp_tkn_rx_cb,
					bbdd_bfdd_bfddp_tkn_destroy,
					tkn, error);
	if (ssk_cbs == NULL)
		goto destroy_tkn;

	peer_cbs = bbdd_ssk_peer_add_cbs(peer,
					 NULL,
					 bbdd_bfdd_d_peer_done_cb,
					 &bfdd_d->base, error);
	if (peer_cbs == NULL)
		goto destroy_tkn;

	*bfdd_d = (struct bbdd_bfdd_d) {
		.base = {
			.tkn = tkn,

			.pctx = pctx,
			.mon = mon,
			.cbs = *cbs,
		},
		.peer = peer,
		.peer_cbs = peer_cbs,
	};
	return bfdd_d;

destroy_tkn:
	bbdd_util_ssk_bfddp_tkn_destroy(tkn);
free_bfdd_d:
	free(bfdd_d);
	return NULL;
}

static int bbdd_bfdd_write_enqueue(struct bbdd_ssk_peer *peer,
				   struct bbdd_mon *mon,
				   const struct bfddp_message *msg,
				   char **error)
{
	uint16_t msglen = bbdd_ntoh16(msg->header.length);
	int rc;

	rc = bbdd_ssk_peer_nq(peer, (const char *) msg, msglen, error);
	if (rc != 0)
		return rc;

	bbdd_bfdd_mon_send_o(mon, msg);
	return 0;
}

int bbdd_bfdd_c_reply_counters(struct bbdd_bfdd_c *bfdd_c,
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

	return bbdd_bfdd_write_enqueue(bbdd_ssk_c_peer(bfdd_c->ssc),
				       bfdd_c->base.mon,
				       &msg, error);
}

static void bbdd_bfdd_echo_peer_done(struct bbdd_ssk_peer *, void *data);

static struct bbdd_bfdd_echo_peer *
bbdd_bfdd_echo_peer_init(struct bbdd_bfdd_b *bfdd_b, struct bbdd_ssk_peer *peer,
			 struct json_object *id, bool is_dp, char **error)
{
	struct bbdd_bfdd_echo_peer *epeer;
	struct bbdd_ssk_cbs *ssk_cbs;

	bbdd_mon_send_debug(bfdd_b->mon, "echo peer init");

	epeer = malloc(sizeof(*epeer));
	if (epeer == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	ssk_cbs = bbdd_ssk_peer_add_cbs(peer, NULL,
					bbdd_bfdd_echo_peer_done,
					epeer, error);
	if (ssk_cbs == NULL)
		goto epeer_free;

	*epeer = (struct bbdd_bfdd_echo_peer) {
		.bfdd_b = bfdd_b,
		.peer = peer,
		.id = json_object_get(id),
		.is_dp = is_dp,
		.ssk_cbs = ssk_cbs,
	};

	DL_APPEND(bfdd_b->echo_peers, epeer);
	return epeer;

epeer_free:
	free(epeer);
	return NULL;
}

static void bbdd_bfdd_echo_peer_fini(struct bbdd_bfdd_echo_peer *epeer)
{
	bbdd_mon_send_debug(epeer->bfdd_b->mon, "echo peer fini");

	DL_DELETE(epeer->bfdd_b->echo_peers, epeer);

	/* The peer cleans up the callbacks when it's done, but peer_fini() is
	 * also used on error paths for cleanup. */
	bbdd_ssk_peer_del_cbs(epeer->peer, epeer->ssk_cbs);

	json_object_put(epeer->id);
	free(epeer);
}

static void bbdd_bfdd_echo_peer_done(struct bbdd_ssk_peer *, void *data)
{
	struct bbdd_bfdd_echo_peer *epeer = data;

	bbdd_mon_send_debug(epeer->bfdd_b->mon, "echo peer gone");
	bbdd_bfdd_echo_peer_fini(epeer);
}

static void bbdd_bfdd_echo_peers_free(struct bbdd_bfdd_b *bfdd_b)
{
	struct bbdd_bfdd_echo_peer *epeer, *tmp;

	DL_FOREACH_SAFE(bfdd_b->echo_peers, epeer, tmp)
		bbdd_bfdd_echo_peer_fini(epeer);
}

static void bbdd_bfdd_echo_respond_no_client(struct bbdd_ssk_peer *peer,
					     struct json_object *id)
{
	bbdd_util_jrpc_respond_interr(peer, id, "No BFDD client connected");
}

static int bbdd_bfdd_send_echo(struct bbdd_ssk_peer *peer, struct bbdd_mon *mon,
			       uint16_t msg_id, uint64_t time_us,
			       bool is_dp, char **error)
{
	struct bfddp_message msg = {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(ECHO_REQUEST),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.echo)),
		.data.echo = {
			.dp_time   = is_dp ? bbdd_hton64(time_us)
					   : bbdd_hton64(0),
			.bfdd_time = is_dp ? bbdd_hton64(0)
					   : bbdd_hton64(time_us),
		},
	};

	return bbdd_bfdd_write_enqueue(peer, mon, &msg, error);
}

static void bbdd_bfdd_echo_handle_start(struct bbdd_bfdd_b *bfdd_b,
					struct bbdd_ssk_peer *json_peer,
					struct bbdd_ssk_peer *bfdd_peer,
					struct json_object *id, bool is_dp)
{
	struct bbdd_bfdd_echo_peer *epeer;
	uint64_t ts;
	char *error;
	int rc;

	epeer = bbdd_bfdd_echo_peer_init(bfdd_b, json_peer, id, is_dp, &error);
	if (epeer == NULL)
		goto err;

	ts = bbdd_util_now();
	rc = bbdd_bfdd_send_echo(bfdd_peer, bfdd_b->mon, 1, ts, is_dp,
				 &error);
	if (rc != 0)
		goto epeer_fini;

	return;

epeer_fini:
	bbdd_bfdd_echo_peer_fini(epeer);
err:
	bbdd_util_jrpc_respond_interr_err(json_peer, id, &error);
}

void bbdd_bfdd_c_echo_handle_start(struct bbdd_bfdd_c *bfdd_c,
				   struct bbdd_ssk_peer *json_peer,
				   struct json_object *id)
{
	struct bbdd_ssk_peer *bfdd_peer;

	if (bfdd_c == NULL)
		return bbdd_bfdd_echo_respond_no_client(json_peer, id);

	bfdd_peer = bbdd_ssk_c_peer(bfdd_c->ssc);
	bbdd_bfdd_echo_handle_start(&bfdd_c->base, json_peer, bfdd_peer,
				    id, true);
}

void bbdd_bfdd_d_echo_handle_start(struct bbdd_bfdd_d *bfdd_d,
				   struct bbdd_ssk_peer *json_peer,
				   struct json_object *id)
{
	if (bfdd_d == NULL)
		return bbdd_bfdd_echo_respond_no_client(json_peer, id);

	bbdd_bfdd_echo_handle_start(&bfdd_d->base, json_peer, bfdd_d->peer,
				    id, false);
}

static void bbdd_bfdd_echo_handle_reply(struct bbdd_bfdd_b *bfdd_b,
					const struct bfddp_message *msg)
{
	uint64_t bfdd_time = bbdd_ntoh64(msg->data.echo.bfdd_time);
	uint64_t dp_time = bbdd_ntoh64(msg->data.echo.dp_time);
	struct bbdd_bfdd_echo_peer *epeer;

	DL_FOREACH(bfdd_b->echo_peers, epeer) {
		if (epeer->is_dp)
			bbdd_util_jrpc_respond_echo(epeer->peer, epeer->id,
						    dp_time, bfdd_time,
						    bfdd_b->mon);
		else
			bbdd_util_jrpc_respond_echo(epeer->peer, epeer->id,
						    bfdd_time, dp_time,
						    bfdd_b->mon);
	}

	bbdd_bfdd_echo_peers_free(bfdd_b);
}

void bbdd_bfdd_c_echo_handle_reply(struct bbdd_bfdd_c *bfdd_c,
				   const struct bfddp_message *msg)
{
	bbdd_bfdd_echo_handle_reply(&bfdd_c->base, msg);
}

void bbdd_bfdd_d_echo_handle_reply(struct bbdd_bfdd_d *bfdd_d,
				   const struct bfddp_message *msg)
{
	bbdd_bfdd_echo_handle_reply(&bfdd_d->base, msg);
}

static int bbdd_bfdd_reply_echo(struct bbdd_ssk_peer *peer,
				struct bbdd_mon *mon, uint16_t msg_id,
				const struct bfddp_echo *in_echo,
				bool is_dp, char **error)
{
	uint64_t now = bbdd_util_now();
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = bbdd_hton16(ECHO_REPLY),
		.header.id = bbdd_hton16(msg_id),
		.header.length = bbdd_hton16(sizeof(msg.header) +
					     sizeof(msg.data.echo)),

		.data.echo = (struct bfddp_echo) {
			.dp_time   = is_dp ? bbdd_hton64(now)
					   : in_echo->dp_time,
			.bfdd_time = is_dp ? in_echo->bfdd_time
					   : bbdd_hton64(now),
		},
	};

	return bbdd_bfdd_write_enqueue(peer, mon, &msg, error);
}

int bbdd_bfdd_c_reply_echo(struct bbdd_bfdd_c *bfdd_c, uint16_t msg_id,
			   const struct bfddp_echo *in_echo, char **error)
{
	return bbdd_bfdd_reply_echo(bbdd_ssk_c_peer(bfdd_c->ssc),
				    bfdd_c->base.mon, msg_id, in_echo, true,
				    error);
}

int bbdd_bfdd_d_reply_echo(struct bbdd_bfdd_d *bfdd_d, uint16_t msg_id,
			   const struct bfddp_echo *in_echo, char **error)
{
	return bbdd_bfdd_reply_echo(bfdd_d->peer, bfdd_d->base.mon,
				    msg_id, in_echo, false, error);
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

	bbdd_err_fmt(error, "Could not translate ifindex %d to interface name: %m",
		     ifindex);
	return -EINVAL;
}

int bbdd_bfdd_c_send_state_change(struct bbdd_bfdd_c *bfdd_c,
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

	return bbdd_bfdd_write_enqueue(bbdd_ssk_c_peer(bfdd_c->ssc),
				       bfdd_c->base.mon, &msg, error);
}

int bbdd_bfdd_d_add_session(struct bbdd_bfdd_d *bfdd_d,
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

	return bbdd_bfdd_write_enqueue(bfdd_d->peer, bfdd_d->base.mon, &msg,
				       error);
}

int bbdd_bfdd_d_del_session(struct bbdd_bfdd_d *bfdd_d, uint16_t msg_id,
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

	return bbdd_bfdd_write_enqueue(bfdd_d->peer, bfdd_d->base.mon, &msg,
				       error);
}

int bbdd_bfdd_d_request_counters(struct bbdd_bfdd_d *bfdd_d, uint16_t msg_id,
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

	return bbdd_bfdd_write_enqueue(bfdd_d->peer, bfdd_d->base.mon, &msg,
				       error);
}

static void bbdd_bfdd_close_b(struct bbdd_bfdd_b *bfdd_b)
{
	struct bbdd_bfdd_echo_peer *epeer;

	DL_FOREACH(bfdd_b->echo_peers, epeer)
		bbdd_util_jrpc_respond_interr(epeer->peer, epeer->id,
					      "BFDD client disconnect");
	bbdd_bfdd_echo_peers_free(bfdd_b);
}

void bbdd_bfdd_close_c(struct bbdd_bfdd_c *bfdd_c)
{
	bbdd_ssk_close_c(bfdd_c->ssc);
	bbdd_bfdd_close_b(&bfdd_c->base);
	free(bfdd_c);
}

void bbdd_bfdd_close_d(struct bbdd_bfdd_d *bfdd_d)
{
	if (bfdd_d->peer != NULL)
		bbdd_ssk_peer_destroy(bfdd_d->peer);

	bbdd_bfdd_close_b(&bfdd_d->base);
	free(bfdd_d);
}

static int bbdd_bfdd_session_to_c_addr(struct bbdd_c_session_addr *to,
				       const struct in6_addr *from,
				       int af, char **error)
{
	const char *ret;

	ret = inet_ntop(af, from, to->str, sizeof(to->str));
	if (ret == NULL) {
		bbdd_err_fmt(error, "Failed to convert address: %m");
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
		bbdd_err_fmt(error, "Echo not supported");
		return -1;
	}

	if (flags & SESSION_DEMAND) {
		bbdd_err_fmt(error, "Demand mode not supported");
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

	{
		uint32_t hold_time_ms = bbdd_ntoh32(fsess->hold_time);

		/* 4G us is ~71 minutes. It's unlikely anybody would need such
		 * long periods in practice, but let's be explicit and bounce
		 * instead of wrapping around or saturating silently. */
		if (hold_time_ms > UINT32_MAX / 1000) {
			bbdd_err_fmt(error, "hold_time %u ms->us overflows uint32_t",
				     hold_time_ms);
			return -1;
		}

		csess->hold_time_us = hold_time_ms * 1000;
	}
	csess->hold_time_us_seen = 1;

	csess->ttl = fsess->ttl;
	csess->ttl_seen = 1;

	csess->detect_mult = fsess->detect_mult;
	csess->detect_mult_seen = 1;

	/* If an interface name is too long, it will be truncated, and will
	 * subsequently fail validation. We therefore do not mind the
	 * truncation. */
#define copy_name(dst, src) do {					\
		size_t _n = strnlen((src), sizeof(dst) - 1);		\
		memcpy((dst), (src), _n);				\
		(dst)[_n] = '\0';					\
	} while (0)

	if (bbdd_ntoh32(fsess->ifindex) == 0) {
		csess->netif.unset = true;
	} else {
		csess->netif.ifindex = bbdd_ntoh32(fsess->ifindex);
		csess->netif.ifindex_seen = 1;

		if (fsess->ifname[0] != '\0') {
			copy_name(csess->netif.name, fsess->ifname);
			csess->netif.name_seen = 1;
		}
	}

	if (bbdd_ntoh32(cmsess->vrf_id) == 0) {
		csess->vrf.netif.unset = true;
	} else {
		csess->vrf.table = bbdd_ntoh32(cmsess->vrf_id);
		csess->vrf.table_seen = 1;

		if (cmsess->vrfname[0] != '\0') {
			copy_name(csess->vrf.netif.name, cmsess->vrfname);
			csess->vrf.netif.name_seen = 1;
		}
	}
#undef copy_name

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

	bbdd_err_fmt(error, "DP_ADD_SESSION: Invalid length: got %u, expected %u or %u",
		     length, std_len, cml_len);
	return -EMSGSIZE;
}

static int bbdd_bfdd_format_add_session(const struct bfddp_message *msg,
					const char *method,
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
		.method = method,
		.params = params,
	};
	return 0;

put_sess_obj:
	json_object_put(sess_obj);
put_params:
	json_object_put(params);
err:
	bbdd_err_fmt(error, "%m");
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
	bbdd_err_fmt(error, "%m");
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
	bbdd_err_fmt(error, "%m");
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
	bbdd_err_fmt(error, "%m");
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
	bbdd_err_fmt(error, "%m");
	return -1;
}

#define BBDD_BFDD_I_O(IN, NAME) ((IN) ? ("bfddi:" NAME) : ("bfddo:" NAME))

static int bbdd_bfdd_msg_format_mon(const struct bfddp_message *msg,
				    struct bbdd_mon_message *mon_msg,
				    bool in, char **error)
{
	enum bfddp_message_type bmt = bbdd_ntoh16(msg->header.type);

	switch (bmt) {
		const char *method;
		uint32_t lid;

	case DP_ADD_SESSION:
		method = BBDD_BFDD_I_O(in, "sess-add");
		return bbdd_bfdd_format_add_session(msg, method, mon_msg, error);

	case DP_DELETE_SESSION:
		method = BBDD_BFDD_I_O(in, "sess-del");
		lid = bbdd_ntoh32(msg->data.session.lid);
		return bbdd_bfdd_format_lid_msg(lid, method, mon_msg, error);

	case DP_REQUEST_SESSION_COUNTERS:
		method = BBDD_BFDD_I_O(in, "sess-cnt-req");
		lid = bbdd_ntoh32(msg->data.counters_req.lid);
		return bbdd_bfdd_format_lid_msg(lid, method, mon_msg, error);

	case BFD_STATE_CHANGE:
		method = BBDD_BFDD_I_O(in, "state-change");
		return bbdd_bfdd_format_state_change(&msg->data.state, method,
						     mon_msg, error);

	case ECHO_REQUEST:
		method = BBDD_BFDD_I_O(in, "echo-req");
		return bbdd_bfdd_format_echo(&msg->data.echo, method, mon_msg,
					     error);
	case ECHO_REPLY:
		method = BBDD_BFDD_I_O(in, "echo-rep");
		return bbdd_bfdd_format_echo(&msg->data.echo, method, mon_msg,
					     error);
	case BFD_SESSION_COUNTERS:
		method = BBDD_BFDD_I_O(in, "sess-cnt-rep");
		return bbdd_bfdd_msg_format_bare(method, mon_msg);

	default:
		return bbdd_bfdd_format_unknown(bmt, mon_msg, error);
	}
}

static void bbdd_bfdd_mon_send(struct bbdd_mon *mon,
			       const struct bfddp_message *msg, bool in)
{
	struct bbdd_mon_message mon_msg;
	enum bbdd_mon_topic topic;
	char *error;
	int rc;

	if (in)
		topic = BBDD_MON_TOPIC_bfddi;
	else
		topic = BBDD_MON_TOPIC_bfddo;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	rc = bbdd_bfdd_msg_format_mon(msg, &mon_msg, in, &error);
	if (rc != 0)
		return bbdd_mon_senderr(mon, &error, "Failed to format bfdd monitor message");

	bbdd_mon_send(mon, &mon_msg, topic);
}

void bbdd_bfdd_mon_send_i(struct bbdd_mon *mon, const struct bfddp_message *msg)
{
	bbdd_bfdd_mon_send(mon, msg, true);
}

void bbdd_bfdd_mon_send_o(struct bbdd_mon *mon, const struct bfddp_message *msg)
{
	bbdd_bfdd_mon_send(mon, msg, false);
}
