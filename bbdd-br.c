// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE
#include "bbdd-br.h"

#include <assert.h>
#include <poll.h>
#include <stdio.h>
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
#include "bfddp_packet.h"

struct bbdd_br {
	struct bbdd_nl *nl;
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	struct bbdd_sock ctl;
	struct bbdd_sock bfdd_server;
	int bfdd_cli_fd;
};

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

static void bbdd_br_bfdd_client_close(struct bbdd_br *br)
{
	int rc;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Client disconnected.\n");

	assert(br->bfdd_cli_fd >= 0);
	rc = bbdd_poll_unset_fd(br->pctx, br->bfdd_cli_fd);
	assert(rc == 0);

	close(br->bfdd_cli_fd);
	br->bfdd_cli_fd = -1;
}

static int bbdd_br_bfdd_recv(struct bbdd_poll_ctx *pctx, short revents,
			     void *data, char **error)
{
	struct bbdd_br *br = data;

	if (revents & POLLHUP) {
		bbdd_br_bfdd_client_close(br);
		return 0;
	}

	return 0;
}

static int bbdd_br_bfdd_client_accept(struct bbdd_poll_ctx *pctx, short revents,
				      void *arg, char **error)
{
	struct bbdd_br *br = arg;
	int fd;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Client connected.\n");

	fd = accept4(br->bfdd_server.fd, NULL, NULL,
		     SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		bbdd_util_fmterr(error, "accept4: %m");
		return -1;
	}

	assert(br->bfdd_cli_fd < 0);
	br->bfdd_cli_fd = fd;

	return bbdd_poll_set_fd(pctx, fd, POLLIN | POLLHUP, bbdd_br_bfdd_recv,
				br, error);
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
	struct bbdd_br br = {
		.bfdd_cli_fd = -1,
	};
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

	bbdd_mon_send_monitor_end(br.mon);

	bbdd_poll_unset_signals(br.pctx);
	if (br.bfdd_cli_fd >= 0)
		close(br.bfdd_cli_fd);
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
