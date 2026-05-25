// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE
#include "bbdd-br.h"

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <json-c/json_object.h>

#include "bbdd.h"
#include "bbdd-bfdd.h"
#include "bbdd-c.h"
#include "bbdd-d.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"
#include "bfddp.h"
#include "bfddp_packet.h"

struct bbdd_br_echo {
	struct bbdd_sock peer;
	struct json_object *id;
};

struct bbdd_br_stats {
	struct bbdd_sock peer;
	struct json_object *id;
	uint32_t discr;
};

struct bbdd_br {
	struct bbdd_nl *nl;
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	struct bbdd_sock ctl;
	struct bbdd_sock bfdd_server;
	struct bbdd_bfdd *bfdd; /* non-NULL while a bfdd client is connected */

	struct bbdd_br_echo *echo; /* non-NULL = echo awaiting ECHO_REPLY */
	struct bbdd_br_stats *stats; /* non-NULL = session-stats awaiting
				      * BFD_SESSION_COUNTERS */
};

static struct bbdd_br_echo *bbdd_br_echo_alloc(struct bbdd_sock *peer,
					       struct json_object *id,
					       char **error)
{
	struct bbdd_br_echo *echo;

	echo = malloc(sizeof(*echo));
	if (echo == NULL) {
		bbdd_util_fmterr(error, "Could not allocate echo context: %m");
		return NULL;
	}

	*echo = (struct bbdd_br_echo) {
		.peer = *peer,
		.id = json_object_get(id),
	};
	return echo;
}

static void bbdd_br_echo_free(struct bbdd_br_echo *echo)
{
	json_object_put(echo->id);
	free(echo);
}

static void bbdd_br_echo_close(struct bbdd_br_echo *echo, const char *msg)
{
	bbdd_util_jrpc_respond_interr(&echo->peer, echo->id, msg);
	bbdd_br_echo_free(echo);
}

static struct bbdd_br_stats *bbdd_br_stats_alloc(struct bbdd_sock *peer,
						  struct json_object *id,
						  uint32_t discr,
						  char **error)
{
	struct bbdd_br_stats *stats;

	stats = malloc(sizeof(*stats));
	if (stats == NULL) {
		bbdd_util_fmterr(error, "Could not allocate stats context: %m");
		return NULL;
	}

	*stats = (struct bbdd_br_stats) {
		.peer = *peer,
		.id = json_object_get(id),
		.discr = discr,
	};
	return stats;
}

static void bbdd_br_stats_free(struct bbdd_br_stats *stats)
{
	json_object_put(stats->id);
	free(stats);
}

static void bbdd_br_stats_close(struct bbdd_br_stats *stats, const char *msg)
{
	bbdd_util_jrpc_respond_interr(&stats->peer, stats->id, msg);
	bbdd_br_stats_free(stats);
}

static void bbdd_br_bfdd_client_close(struct bbdd_br *br)
{
	bbdd_mon_send_debug(br->mon, "bfdd: Client disconnected");

	assert(br->bfdd != NULL);
	bbdd_bfdd_close(br->bfdd);
	br->bfdd = NULL;

	if (br->echo != NULL) {
		bbdd_br_echo_close(br->echo, "BFDD client disconnect");
		br->echo = NULL;
	}

	if (br->stats != NULL) {
		bbdd_br_stats_close(br->stats, "BFDD client disconnect");
		br->stats = NULL;
	}
}

static void bbdd_br_bfdd_handle_echo_reply(struct bbdd_br *br,
					   const struct bfddp_message *msg)
{
	uint64_t dp_time = bbdd_ntoh64(msg->data.echo.dp_time);
	uint64_t bfdd_time = bbdd_ntoh64(msg->data.echo.bfdd_time);
	struct json_object *result;
	struct json_object *resp;
	int rc;

	if (br->echo == NULL)
		return;

	resp = bbdd_jrpc_new_object(br->echo->id);
	if (resp == NULL)
		goto err_memerr;

	result = json_object_new_object();
	if (result == NULL)
		goto put_resp;

	if (bbdd_jrpc_append_uint64(result, "ts", bfdd_time) ||
	    bbdd_jrpc_append_uint64(result, "reply_ts", dp_time))
		goto put_result;

	rc = bbdd_jrpc_append_obj(resp, "result", &result);
	if (rc != 0)
		goto put_result;

	bbdd_util_jrpc_send(&br->echo->peer, resp);
	json_object_put(resp);
	goto out;

put_result:
	json_object_put(result);
put_resp:
	json_object_put(resp);
err_memerr:
	bbdd_util_jrpc_respond_memerr(&br->echo->peer, br->echo->id);
out:
	bbdd_br_echo_free(br->echo);
	br->echo = NULL;
}

static int bbdd_br_jrpc_dissect_select_discr(struct json_object *select_obj,
					     uint32_t *discr, char **error)
{
	enum {
		pol_discr,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_discr] = { .key = "discr", .type = json_type_int,
				.required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(select_obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	return bbdd_jrpc_get_uint32(values[pol_discr], discr, error);
}

static int bbdd_br_jrpc_dissect_params_stats(struct json_object *params_obj,
					     uint32_t *discr, char **error)
{
	enum {
		pol_select,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_select] = { .key = "select", .type = json_type_object,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params_obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	return bbdd_br_jrpc_dissect_select_discr(values[pol_select], discr,
						 error);
}

static void bbdd_br_bfdd_handle_session_counters(struct bbdd_br *br,
						 const struct bfddp_message *msg)
{
	const struct bfddp_session_counters *cnt = &msg->data.session_counters;
	struct json_object *resp;
	struct json_object *result_obj;
	struct json_object *array;
	struct json_object *entry_obj;
	struct json_object *stats_obj;

	if (br->stats == NULL)
		return;

	resp = bbdd_jrpc_new_object(br->stats->id);
	if (resp == NULL)
		goto err;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_resp;

	array = json_object_new_array();
	if (array == NULL)
		goto put_result_obj;

	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		goto put_array;

	stats_obj = json_object_new_object();
	if (stats_obj == NULL)
		goto put_entry_obj;

	if (bbdd_jrpc_append_uint64(stats_obj, "rx_bytes",
				    bbdd_ntoh64(cnt->control_input_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_packets",
				    bbdd_ntoh64(cnt->control_input_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_bytes",
				    bbdd_ntoh64(cnt->control_output_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_packets",
				    bbdd_ntoh64(cnt->control_output_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_echo_bytes",
				    bbdd_ntoh64(cnt->echo_input_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_echo_packets",
				    bbdd_ntoh64(cnt->echo_input_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_echo_bytes",
				    bbdd_ntoh64(cnt->echo_output_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_echo_packets",
				    bbdd_ntoh64(cnt->echo_output_packets)) ||

	    bbdd_jrpc_append_uint64(entry_obj, "discr", br->stats->discr) ||
	    bbdd_jrpc_append_obj(entry_obj, "stats", &stats_obj) ||

	    bbdd_jrpc_array_append_obj(array, &entry_obj) ||
	    bbdd_jrpc_append_obj(result_obj, "sessions", &array) ||
	    bbdd_jrpc_append_obj(resp, "result", &result_obj))
		goto put_stats_obj;

	bbdd_util_jrpc_send(&br->stats->peer, resp);
	json_object_put(resp);
	bbdd_br_stats_free(br->stats);
	br->stats = NULL;
	return;

put_stats_obj:
	json_object_put(stats_obj);
put_entry_obj:
	json_object_put(entry_obj);
put_array:
	json_object_put(array);
put_result_obj:
	json_object_put(result_obj);
put_resp:
	json_object_put(resp);
err:
	bbdd_util_jrpc_respond_memerr(&br->stats->peer, br->stats->id);
	bbdd_br_stats_free(br->stats);
	br->stats = NULL;
}

static int
bbdd_br_jrpc_dissect_params_session_add(struct bbdd_br *br,
					struct json_object *params_obj,
					struct bbdd_c_session *csess,
					char **error)
{
	enum {
		pol_change,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_change] = { .key = "change", .type = json_type_object,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params_obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	return bbdd_d_jrpc_dissect_validate_session(values[pol_change],
						    csess, "change",
						    br->nl, error);
}

static void bbdd_br_handle_session_add(struct bbdd_br *br, struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	struct bbdd_c_session csess;
	char *error;
	int rc;

	if (br->bfdd == NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "No BFDD client connected");

	rc = bbdd_br_jrpc_dissect_params_session_add(br, params_obj, &csess,
						     &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	rc = bbdd_bfdd_add_session(br->bfdd, br->nl, &csess, 1, &error);
	if (rc == -EINVAL)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);
	else if (rc != 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_br_handle_session_del(struct bbdd_br *br, struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	uint32_t discr;
	char *error;
	int rc;

	if (br->bfdd == NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "No BFDD client connected");

	rc = bbdd_br_jrpc_dissect_params_stats(params_obj, &discr, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	rc = bbdd_bfdd_del_session(br->bfdd, 1, discr, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_br_handle_echo(struct bbdd_br *br, struct bbdd_sock *peer,
				struct json_object *params_obj,
				struct json_object *id)
{
	enum {
		pol_ts,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_ts] = { .key = "ts", .type = json_type_int, .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	uint64_t ts;
	char *error;
	int rc;

	if (br->bfdd == NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "No BFDD client connected");

	if (br->echo != NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "Echo already pending");

	/* Parse the request for validation's sake, but we ignore the timestamp
	 * and use our own. The goal here is to measure latency from the bridge
	 * to the daemon, not the overall latency of the CLI-bridge-daemon
	 * system. Bridge performance is not interesting. */

	rc = bbdd_jrpc_dissect(params_obj, policy, seen, values,
			       ARRAY_SIZE(policy), &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	br->echo = bbdd_br_echo_alloc(peer, id, &error);
	if (br->echo == NULL)
		goto err;

	ts = bbdd_util_now();
	rc = bbdd_bfdd_send_echo(br->bfdd, 1, ts, &error);
	if (rc != 0)
		goto echo_free;

	return;

echo_free:
	bbdd_br_echo_free(br->echo);
	br->echo = NULL;
err:
	bbdd_util_jrpc_respond_interr_err(peer, id, &error);
}

static void bbdd_br_handle_session_stats(struct bbdd_br *br,
					 struct bbdd_sock *peer,
					 struct json_object *params_obj,
					 struct json_object *id)
{
	uint32_t discr;
	char *error;
	int rc;

	if (br->bfdd == NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "No BFDD client connected");

	if (br->stats != NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "Session stats already pending");

	rc = bbdd_br_jrpc_dissect_params_stats(params_obj, &discr, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	br->stats = bbdd_br_stats_alloc(peer, id, discr, &error);
	if (br->stats == NULL)
		goto err;

	rc = bbdd_bfdd_request_counters(br->bfdd, 1, discr, &error);
	if (rc != 0)
		goto stats_free;

	return;

stats_free:
	bbdd_br_stats_free(br->stats);
	br->stats = NULL;
err:
	bbdd_util_jrpc_respond_interr_err(peer, id, &error);
}

static void bbdd_br_handle_stop(struct bbdd_br *br, struct bbdd_sock *peer,
				struct json_object *params_obj,
				struct json_object *id)
{
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	bbdd_poll_request_quit(br->pctx);
	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_br_handle_unhandled(struct bbdd_sock *peer,
				     const char *method,
				     struct json_object *id)
{
	bbdd_util_jrpc_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_br_handle_method(struct bbdd_sock *peer,
				  const char *method,
				  struct json_object *params_obj,
				  struct json_object *id,
				  void *data)
{
	struct bbdd_br *br = data;

	if (strcmp(method, "stop") == 0)
		bbdd_br_handle_stop(br, peer, params_obj, id);
	else if (strcmp(method, "ping") == 0)
		bbdd_d_handle_ping(peer, params_obj, id);
	else if (strcmp(method, "echo") == 0)
		bbdd_br_handle_echo(br, peer, params_obj, id);
	else if (strcmp(method, "session-add") == 0)
		bbdd_br_handle_session_add(br, peer, params_obj, id);
	else if (strcmp(method, "session-del") == 0)
		bbdd_br_handle_session_del(br, peer, params_obj, id);
	else if (strcmp(method, "session-stats") == 0)
		bbdd_br_handle_session_stats(br, peer, params_obj, id);
	else if (strcmp(method, "monitor-subscribe") == 0)
		bbdd_d_handle_monitor_subscribe(br->mon, peer, params_obj, id);
	else
		bbdd_br_handle_unhandled(peer, method, id);
}

static int bbdd_br_ctl_recv(struct bbdd_poll_ctx *, short revents,
			    void *data, char **)
{
	struct bbdd_br *br = data;

	assert(revents == POLLIN);
	bbdd_util_ctl_activity(&br->ctl, br->mon, bbdd_br_handle_method, br);
	return 0;
}

static void __bbdd_br_bfdd_hangup(struct bbdd_br *br, struct bbdd_bfdd *bfdd)
{
	assert(br->bfdd == bfdd);
	bbdd_br_bfdd_client_close(br);
}

static void
bbdd_br_bfdd_handle_state_change(struct bbdd_br *br,
				 const struct bfddp_message *msg)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_session;
	struct bbdd_mon_message mon_msg;
	char *error;
	int rc;

	/* For session change messages, we don't really have good options
	 * besides sending as a monitor message in case anyone is watching. This
	 * message should be on a session: topic. Note that we have already
	 * produced a message on a bfdd: topic, so this may be duplicate. I
	 * think that's OK, it's the consistent thing to do. bfdd: is a generic
	 * topic for all BFDD messages, whereas BFD_STATE_CHANGE specifically
	 * produces a session: message because it's a session change. */

	if (!bbdd_mon_topic_active(br->mon, topic))
		return;

	rc = bbdd_bfdd_format_state_change(&msg->data.state, "session:change",
					   &mon_msg, &error);
	if (rc != 0)
		return bbdd_mon_senderr(br->mon, &error, "Failed to forward BFD_STATE_CHANGE message");

	bbdd_mon_send(br->mon, &mon_msg, topic);
}

static void __bbdd_br_bfdd_message_cb(struct bbdd_br *br,
				      struct bbdd_bfdd *bfdd,
				      struct bfddp_message *msg)
{
	enum bfddp_message_type bmt;
	char *error;

	if (msg->header.version != 1) {
		bbdd_util_fmterr(&error, "bfdd: Wrong message version number %d",
				 msg->header.version);
		goto senderr;
	}

	bbdd_bfdd_mon_send_i(br->mon, msg);

	bmt = bbdd_ntoh16(msg->header.type);
	switch (bmt) {
	case ECHO_REPLY:
		return bbdd_br_bfdd_handle_echo_reply(br, msg);
	case BFD_SESSION_COUNTERS:
		return bbdd_br_bfdd_handle_session_counters(br, msg);
	case BFD_STATE_CHANGE:
		return bbdd_br_bfdd_handle_state_change(br, msg);
	case ECHO_REQUEST:
	case DP_ADD_SESSION:
	case DP_DELETE_SESSION:
	case DP_REQUEST_SESSION_COUNTERS:
	default:
		bbdd_util_fmterr(&error, "bfdd: Invalid message type %d", bmt);
		goto senderr;
	}

senderr:
	bbdd_mon_senderr(br->mon, &error, "bfdd");
}

static void bbdd_br_bfdd_hangup_cb(struct bbdd_bfdd *bfdd, void *data)
{
	struct bbdd_br *br = data;

	__bbdd_br_bfdd_hangup(br, bfdd);
}

static void bbdd_br_bfdd_sockerr_cb(struct bbdd_bfdd *bfdd, const char *error,
				    void *data)
{
	struct bbdd_br *br = data;

	__bbdd_br_bfdd_hangup(br, bfdd);
}

static int bbdd_br_bfdd_message_cb(struct bbdd_bfdd *bfdd,
				   struct bfddp_message *msg,
				   void *data, char **error)
{
	struct bbdd_br *br = data;

	__bbdd_br_bfdd_message_cb(br, bfdd, msg);
	return 0;
}

static int bbdd_br_bfdd_client_accept(struct bbdd_poll_ctx *pctx, short revents,
				      void *arg, char **error)
{
	struct bbdd_br *br = arg;
	struct bbdd_bfdd_cbs cbs;
	int fd;

	bbdd_mon_send_debug(br->mon, "bfdd: Client connected");

	fd = accept4(br->bfdd_server.fd, NULL, NULL,
		     SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		bbdd_util_fmterr(error, "accept4: %m");
		goto err;
	}

	if (br->bfdd != NULL)
		bbdd_br_bfdd_client_close(br);

	cbs = (struct bbdd_bfdd_cbs) {
		.sock_cb_data = br,
		.hangup_cb = bbdd_br_bfdd_hangup_cb,
		.sockerr_cb = bbdd_br_bfdd_sockerr_cb,
		.message_cb = bbdd_br_bfdd_message_cb,
		.sock_free_cb = NULL,
	};
	br->bfdd = bbdd_bfdd_open_client(fd, pctx, br->mon, &cbs, error);
	if (br->bfdd == NULL)
		goto fd_close;

	return 0;

fd_close:
	close(fd);
err:
	bbdd_util_appenderr(error, "BFDD client accept");
	return -1;
}

static int bbdd_br_open_bfdd_server(const struct bbdd_sockaddr *bsa,
				    struct bbdd_sock *sock, char **error)
{
	int rc;

	rc = bbdd_sock_open_sa(bsa, SOCK_STREAM | SOCK_CLOEXEC, sock, error);
	if (rc != 0)
		return rc;

	rc = listen(sock->fd, SOMAXCONN);
	if (rc < 0) {
		bbdd_util_fmterr(error, "listen: %m");
		goto close_sock;
	}

	return 0;

close_sock:
	bbdd_sock_close(sock);
	return -1;
}

static void bbdd_br_close_bfdd_server(struct bbdd_sock *sock)
{
	bbdd_sock_close(sock);
}

static int bbdd_br_do_start(const char *addr, struct bbdd_mon_topics topics)
{
	struct bbdd_br br = {};
	struct bbdd_sockaddr bfdd_bsa;
	char *error;
	int err = 0;

	err = bbdd_sock_parse_addr(addr, &bfdd_bsa, BFD_DATA_PLANE_DEFAULT_PORT,
				   &error);
	if (err != 0) {
		bbdd_util_appenderr(&error, "Failed to parse BFDD address");
		goto out;
	}

	br.nl = bbdd_nl_create(&error);
	if (br.nl == NULL) {
		err = -1;
		goto out;
	}

	br.mon = bbdd_mon_init(&error);
	if (br.mon == NULL)
		goto nl_destroy;

	br.pctx = bbdd_poll_init(br.mon, &error);
	if (br.pctx == NULL) {
		err = -1;
		goto poll_fini;
	}

	err = bbdd_mon_subscribe_cb(br.mon, bbdd_c_monitor_dispatch, NULL,
				    topics, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to subscribe to monitor");
		goto mon_fini;
	}

	err = bbdd_br_open_bfdd_server(&bfdd_bsa, &br.bfdd_server, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to open BFDD server socket");
		goto mon_fini;
	}

	err = bbdd_poll_set_fd(br.pctx, br.bfdd_server.fd, POLLIN,
			       bbdd_br_bfdd_client_accept, &br, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to register BFDD server socket");
		goto bfdd_server_close;
	}

	err = bbdd_sock_open_d(&br.ctl, bbdd_env.sockdir, &error);
	if (err != 0)
		goto bfdd_server_close;

	err = bbdd_poll_set_fd(br.pctx, br.ctl.fd, POLLIN,
			       bbdd_br_ctl_recv, &br, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to register socket for events");
		goto sock_close_d;
	}

	err = bbdd_poll_set_signals(br.pctx, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to set up signal handling");
		goto sock_close_d;
	}

	err = bbdd_poll_loop(br.pctx, &error);
	if (err != 0)
		bbdd_util_printerr(&error, NULL);

	if (br.bfdd != NULL)
		bbdd_br_bfdd_client_close(&br);

	bbdd_mon_send_monitor_end(br.mon);

	bbdd_poll_unset_signals(br.pctx);

sock_close_d:
	bbdd_sock_close_d(&br.ctl);
bfdd_server_close:
	bbdd_br_close_bfdd_server(&br.bfdd_server);
poll_fini:
	bbdd_poll_fini(br.pctx);
mon_fini:
	bbdd_mon_fini(br.mon);
nl_destroy:
	bbdd_nl_destroy(br.nl);
out:
	return err;
}

static void bbdd_br_start_help(void)
{
	fprintf(stderr, "%s",
		"Usage: bbdd bfdd bridge start [TYPE:ADDRESS[:PORT]] [monitor [topics...]]\n"
		"TYPE ::= {ipv4 | ipv6 | unix}\n"
		"Default address is `" BBDD_BFDD_DEFAULT_ADDR "'.\n"
		"\n"
	);
}

int bbdd_br_start(int argc, char **argv, const struct bbdd_mon_topics *topics)
{
	const char *addr = BBDD_BFDD_DEFAULT_ADDR;

	if (argc > 0 && strcmp(*argv, "help") == 0) {
		bbdd_br_start_help();
		return 0;
	}

	if (argc > 0) {
		addr = *argv;
		NEXT_ARG_FWD();
	}

	if (argc > 0) {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	return bbdd_br_do_start(addr, *topics);
}
