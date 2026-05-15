// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-bfdd.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-poll.h"
#include "bbdd-prog-stat.h"
#include "bbdd-util.h"
#include "bfddp.h"

struct bbdd_bfdd {
	struct bfddp_ctx *bctx;
	int fd;
	struct bbdd_poll_ctx *pctx;

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

	if (rv > 0 && bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: received %zd bytes\n", rv);

	return bbdd_bfdd_handle_messages(bfdd, error);
}

static int bbdd_bfdd_write_event(struct bbdd_bfdd *bfdd, char **error)
{
	ssize_t rv;

	rv = bfddp_write(bfdd->bctx);
	if (rv == -1)
		return bbdd_bfdd_fmterr_errno(error);

	if (rv > 0 && bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: sent %zd bytes\n", rv);

	return 0;
}

static int bbdd_bfdd_event(struct bbdd_poll_ctx *pctx, short revents,
			   void *data, char **)
{
	struct bbdd_bfdd *bfdd = data;
	short events = POLLIN;
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

	rv = bbdd_poll_set_fd(pctx, bfdd->fd, POLLOUT,
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
		.cbs = *cbs,
	};

	rc = bbdd_poll_set_fd(pctx, bfdd->fd, POLLIN | POLLOUT | POLLHUP,
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
		.header.type = htons(BFD_SESSION_COUNTERS),
		.header.id = msg_id,
		.header.length = htons(sizeof(msg.header) +
				       sizeof(msg.data.session_counters)),

		.data.session_counters = {
			.lid = htonl(discr),
			.control_input_bytes = htobe64(stats->rx_bytes),
			.control_input_packets = htobe64(stats->rx_packets),
			.control_output_bytes = htobe64(stats->tx_bytes),
			.control_output_packets = htobe64(stats->tx_packets),
			/* echo counters are zero */
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

static uint64_t bbdd_bfdd_now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t) tv.tv_sec) * 1000000 + tv.tv_usec;
}

static int __bbdd_bfdd_send_echo(struct bbdd_bfdd *bfdd,
				 enum bfddp_message_type bmt,
				 uint16_t msg_id,
				 const struct bfddp_echo *in_echo, char **error)
{
	uint64_t dp_time = bbdd_bfdd_now();
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = htons(bmt),
		.header.id = msg_id,
		.header.length = htons(sizeof(msg.header) +
				       sizeof(msg.data.echo)),

		.data.echo = (struct bfddp_echo) {
			.dp_time = htobe64(dp_time),
			.bfdd_time = in_echo->bfdd_time,
		},
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_send_echo(struct bbdd_bfdd *bfdd, uint16_t msg_id, char **error)
{
	struct bfddp_echo echo = {
		.bfdd_time = htobe64(bbdd_bfdd_now()),
	};

	return __bbdd_bfdd_send_echo(bfdd, ECHO_REQUEST, msg_id, &echo, error);
}

int bbdd_bfdd_reply_echo(struct bbdd_bfdd *bfdd,
			 uint16_t msg_id,
			 const struct bfddp_echo *in_echo, char **error)
{
	return __bbdd_bfdd_send_echo(bfdd, ECHO_REPLY, msg_id, in_echo, error);
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
	if (dsess.flags.multihop)
		flags |= SESSION_MULTIHOP;
	if (dsess.flags.cbit)
		flags |= SESSION_CBIT;
	if (dsess.flags.passive)
		flags |= SESSION_PASSIVE;
	if (dsess.flags.shutdown)
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
		.header.type = htons(DP_ADD_SESSION),
		.header.id = msg_id,
		.header.length = htons(length),

		.data.session_cumulus = {
			.session = {
				.flags = htonl(flags),
				.src = src,
				.dst = dst,
				.lid = htonl(dsess.local.discr),
				.min_tx = htonl(dsess.local.timing.min_tx_us),
				.min_rx = htonl(dsess.local.timing.min_rx_us),
				.min_echo_tx = 0,
				.min_echo_rx = 0,
				/* Wire hold_time is in milliseconds. */
				.hold_time = htonl(dsess.hold_time_us / 1000),
				.ttl = dsess.ttl,
				.detect_mult = dsess.local.timing.detect_mult,
				.ifindex = dsess.ifindex,
			},
			.vrf_id = ntohl(dsess.vrf_table),
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
		.header.type = htons(DP_DELETE_SESSION),
		.header.id = msg_id,
		.header.length = htons(sizeof(msg.header) +
				       sizeof(msg.data.session)),

		.data.session.lid = htonl(discr),
	};

	return bbdd_bfdd_write_enqueue(bfdd, &msg, error);
}

int bbdd_bfdd_request_counters(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			       uint32_t discr, char **error)
{
	struct bfddp_message msg;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = htons(DP_REQUEST_SESSION_COUNTERS),
		.header.id = msg_id,
		.header.length = htons(sizeof(msg.header) +
				       sizeof(msg.data.counters_req)),

		.data.counters_req = {
			.lid = htonl(discr),
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
	uint32_t flags = ntohl(fsess->flags);
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
	SET_FLAG(cbit,     SESSION_CBIT);
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

	csess->discr = ntohl(fsess->lid);
	csess->discr_seen = (csess->discr != 0);

	csess->min_tx_us = ntohl(fsess->min_tx);
	csess->min_tx_us_seen = 1;

	csess->min_rx_us = ntohl(fsess->min_rx);
	csess->min_rx_us_seen = 1;

	/* Wire hold_time is in milliseconds; we store microseconds. The
	 * conversion can overflow uint32_t for values above ~4M ms (~71
	 * minutes). Such values make no operational sense for BFD, so saturate
	 * at UINT32_MAX rather than wrapping silently. */
	{
		uint32_t hold_time_ms = ntohl(fsess->hold_time);

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

	if (ntohl(fsess->ifindex) == 0) {
		csess->netif.unset = true;
	} else {
		csess->netif.ifindex = ntohl(fsess->ifindex);
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

	if (cmsess->vrf_id == 0) {
		csess->vrf.netif.unset = true;
	} else {
		csess->vrf.table = ntohl(cmsess->vrf_id);
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
	uint16_t length = ntohs(msg->header.length);
	enum bfddp_message_type bmt;

	bmt = ntohs(msg->header.type);
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

static struct json_object *
bbdd_bfdd_format_add_session(const char *method,
			     const struct bfddp_message *msg, char **error)
{
	struct bbdd_c_session csess = {};
	struct json_object *notif = NULL;
	struct json_object *params = NULL;
	struct json_object *sess_obj = NULL;
	int rc;

	rc = bbdd_bfdd_session_msg_to_c(msg, &csess, error);
	if (rc != 0)
		return NULL;

	notif = bbdd_jrpc_new_notif(method);
	if (notif == NULL)
		goto err;

	params = json_object_new_object();
	if (params == NULL)
		goto put_notif;

	sess_obj = bbdd_c_jrpc_session_obj(&csess);
	if (sess_obj == NULL)
		goto put_params;

	if (bbdd_jrpc_append_obj(params, "session", &sess_obj) ||
	    bbdd_jrpc_append_obj(notif, "params", &params))
		goto put_sess_obj;

	return notif;

put_sess_obj:
	json_object_put(sess_obj);
put_params:
	json_object_put(params);
put_notif:
	json_object_put(notif);
err:
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bfdd_format_lid_msg(const char *method, uint32_t lid, char **error)
{
	struct json_object *notif = NULL;
	struct json_object *params = NULL;

	notif = bbdd_jrpc_new_notif(method);
	if (notif == NULL)
		goto err;

	params = json_object_new_object();
	if (params == NULL)
		goto put_notif;

	if (bbdd_jrpc_append_int(params, "lid", lid) ||
	    bbdd_jrpc_append_obj(notif, "params", &params))
		goto put_params;

	return notif;

put_params:
	json_object_put(params);
put_notif:
	json_object_put(notif);
err:
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

static struct json_object *
bbdd_bfdd_format_bare_notif(const char *method, char **error)
{
	struct json_object *notif;

	notif = bbdd_jrpc_new_notif(method);
	if (notif == NULL)
		bbdd_util_fmterr(error, "%m");
	return notif;
}

static struct json_object *
bbdd_bfdd_format_unknown(const char *method, enum bfddp_message_type bmt,
			 char **error)
{
	struct json_object *notif;
	struct json_object *params;

	notif = bbdd_jrpc_new_notif(method);
	if (notif == NULL)
		goto err;

	params = json_object_new_object();
	if (params == NULL)
		goto put_notif;

	if (bbdd_jrpc_append_int(params, "type", bmt) ||
	    bbdd_jrpc_append_obj(notif, "params", &params))
		goto put_params;

	return notif;

put_params:
	json_object_put(params);
put_notif:
	json_object_put(notif);
err:
	bbdd_util_fmterr(error, "%m");
	return NULL;
}

struct json_object *
bbdd_bfdd_msg_format_mon(const struct bfddp_message *msg, char **error)
{
	enum bfddp_message_type bmt = ntohs(msg->header.type);

	switch (bmt) {
	case DP_ADD_SESSION:
		return bbdd_bfdd_format_add_session("bfdd:sess-add", msg,
						    error);

	case DP_DELETE_SESSION:
		return bbdd_bfdd_format_lid_msg("bfdd:sess-del",
						ntohl(msg->data.session.lid),
						error);

	case DP_REQUEST_SESSION_COUNTERS:
		return bbdd_bfdd_format_lid_msg("bfdd:sess-cnt-req",
						ntohl(msg->data.counters_req.lid),
						error);

	case ECHO_REQUEST:
		return bbdd_bfdd_format_bare_notif("bfdd:echo-req", error);
	case ECHO_REPLY:
		return bbdd_bfdd_format_bare_notif("bfdd:echo-rep", error);
	case BFD_SESSION_COUNTERS:
		return bbdd_bfdd_format_bare_notif("bfdd:sess-cnt-rep", error);
	case BFD_STATE_CHANGE:
		return bbdd_bfdd_format_bare_notif("bfdd:state-change", error);

	default:
		return bbdd_bfdd_format_unknown("bfdd:unknown", bmt, error);
	}
}
