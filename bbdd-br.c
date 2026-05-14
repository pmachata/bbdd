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
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"
#include "bfddp.h"
#include "bfddp_packet.h"

struct bbdd_br_ping {
	struct bbdd_sock peer;
	struct json_object *id;
	struct json_object *params;
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

	struct bbdd_br_ping *ping; /* non-NULL = ping awaiting ECHO_REPLY */
	struct bbdd_br_stats *stats; /* non-NULL = session-stats awaiting
				      * BFD_SESSION_COUNTERS */
};

static struct bbdd_br_ping *bbdd_br_ping_alloc(struct bbdd_sock *peer,
					       struct json_object *params_obj,
					       struct json_object *id,
					       char **error)
{
	struct bbdd_br_ping *ping;

	ping = malloc(sizeof(*ping));
	if (ping == NULL) {
		bbdd_util_fmterr(error, "Could allocate ping context: %m");
		return NULL;
	}

	*ping = (struct bbdd_br_ping) {
		.peer = *peer,
		.id = json_object_get(id),
		.params = json_object_get(params_obj),
	};
	return ping;
}

static void bbdd_br_ping_free(struct bbdd_br_ping *ping)
{
	json_object_put(ping->id);
	json_object_put(ping->params);
	free(ping);
}

static void bbdd_br_ping_close(struct bbdd_br_ping *ping, const char *msg)
{
	bbdd_util_jrpc_respond_interr(&ping->peer, ping->id, msg);
	bbdd_br_ping_free(ping);
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
	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Client disconnected.\n");

	assert(br->bfdd != NULL);
	bbdd_bfdd_close(br->bfdd);
	br->bfdd = NULL;

	if (br->ping != NULL) {
		bbdd_br_ping_close(br->ping, "BFDD client disconnect");
		br->ping = NULL;
	}

	if (br->stats != NULL) {
		bbdd_br_stats_close(br->stats, "BFDD client disconnect");
		br->stats = NULL;
	}
}

static void bbdd_br_bfdd_handle_echo_reply(struct bbdd_br *br)
{
	struct json_object *resp;
	int rc;

	if (br->ping == NULL)
		return;

	resp = bbdd_jrpc_new_object(br->ping->id);
	if (resp == NULL)
		goto err_memerr;

	rc = bbdd_jrpc_append_obj(resp, "result", &br->ping->params);
	if (rc != 0) {
		json_object_put(resp);
		goto err_memerr;
	}

	bbdd_util_jrpc_send(&br->ping->peer, resp);
	json_object_put(resp);
	bbdd_br_ping_free(br->ping);
	br->ping = NULL;
	return;

err_memerr:
	bbdd_util_jrpc_respond_memerr(&br->ping->peer, br->ping->id);
	bbdd_br_ping_free(br->ping);
	br->ping = NULL;
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
				    be64toh(cnt->control_input_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_packets",
				    be64toh(cnt->control_input_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_bytes",
				    be64toh(cnt->control_output_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_packets",
				    be64toh(cnt->control_output_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_echo_bytes",
				    be64toh(cnt->echo_input_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "rx_echo_packets",
				    be64toh(cnt->echo_input_packets)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_echo_bytes",
				    be64toh(cnt->echo_output_bytes)) ||
	    bbdd_jrpc_append_uint64(stats_obj, "tx_echo_packets",
				    be64toh(cnt->echo_output_packets)) ||

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

	// xxx htons not nice here
	rc = bbdd_bfdd_add_session(br->bfdd, br->nl, &csess, htons(1), &error);
	if (rc == -EINVAL)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);
	else if (rc != 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_br_handle_ping(struct bbdd_br *br, struct bbdd_sock *peer,
				struct json_object *params_obj,
				struct json_object *id)
{
	char *error;
	int rc;

	if (br->bfdd == NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "No BFDD client connected");

	if (br->ping != NULL)
		return bbdd_util_jrpc_respond_interr(peer, id,
						     "Ping already pending");

	br->ping = bbdd_br_ping_alloc(peer, params_obj, id, &error);
	if (br->ping == NULL)
		goto err;

	// xxx htons not nice here
	rc = bbdd_bfdd_send_echo(br->bfdd, htons(1), &error);
	if (rc != 0)
		goto ping_free;

	return;

ping_free:
	bbdd_br_ping_free(br->ping);
	br->ping = NULL;
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

	rc = bbdd_bfdd_request_counters(br->bfdd, htons(1), discr, &error);
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
		bbdd_br_handle_ping(br, peer, params_obj, id);
	else if (strcmp(method, "session-add") == 0)
		bbdd_br_handle_session_add(br, peer, params_obj, id);
	else if (strcmp(method, "session-stats") == 0)
		bbdd_br_handle_session_stats(br, peer, params_obj, id);
	else
		bbdd_br_handle_unhandled(peer, method, id);
}

static int bbdd_br_ctl_recv(struct bbdd_poll_ctx *, short revents,
			    void *data, char **)
{
	struct bbdd_br *br = data;

	assert(revents == POLLIN);
	bbdd_util_ctl_activity(&br->ctl, bbdd_br_handle_method, br);
	return 0;
}

static void __bbdd_br_bfdd_hangup(struct bbdd_br *br, struct bbdd_bfdd *bfdd)
{
	assert(br->bfdd == bfdd);
	bbdd_br_bfdd_client_close(br);
}

static void __bbdd_br_bfdd_message(struct bbdd_br *br,
				   struct bbdd_bfdd *bfdd,
				   struct bfddp_message *msg)
{
	enum bfddp_message_type bmt;

	bmt = ntohs(msg->header.type);

	switch (bmt) {
	case ECHO_REPLY:
		return bbdd_br_bfdd_handle_echo_reply(br);
	case BFD_SESSION_COUNTERS:
		return bbdd_br_bfdd_handle_session_counters(br, msg);
	case BFD_STATE_CHANGE:
	case ECHO_REQUEST:
	case DP_ADD_SESSION:
	case DP_DELETE_SESSION:
	case DP_REQUEST_SESSION_COUNTERS:
		break;
	}
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

	__bbdd_br_bfdd_message(br, bfdd, msg);
	return 0;
}

static int bbdd_br_bfdd_client_accept(struct bbdd_poll_ctx *pctx, short revents,
				      void *arg, char **error)
{
	struct bbdd_br *br = arg;
	struct bbdd_bfdd_cbs cbs;
	int fd;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Client connected.\n");

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
	br->bfdd = bbdd_bfdd_open_client(fd, pctx, &cbs, error);
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

	br.pctx = bbdd_poll_init(&error);
	if (br.pctx == NULL) {
		err = -1;
		goto nl_destroy;
	}

	br.mon = bbdd_mon_init(&error);
	if (br.mon == NULL)
		goto poll_fini;

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
mon_fini:
	bbdd_mon_fini(br.mon);
poll_fini:
	bbdd_poll_fini(br.pctx);
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

int bbdd_br_start(int argc, char **argv)
{
	struct bbdd_mon_topics topics = {};
	const char *addr = BBDD_BFDD_DEFAULT_ADDR;
	int rc;

	if (argc > 0 && strcmp(*argv, "help") == 0) {
		bbdd_br_start_help();
		return 0;
	}

	/* Optional socket address — anything that is not "monitor". */
	if (argc > 0 && strcmp(*argv, "monitor") != 0) {
		addr = *argv;
		NEXT_ARG_FWD();
	}

	if (argc > 0 && strcmp(*argv, "monitor") == 0) {
		NEXT_ARG_FWD();
		rc = bbdd_c_monitor_parse_topics(argc, argv, &topics);
		if (rc != 0)
			return rc;
	} else if (argc > 0) {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	} else {
		topics.enabled[BBDD_MON_TOPIC_error] = true;
	}

	return bbdd_br_do_start(addr, topics);
}
