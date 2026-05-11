// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-br.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json_object.h>

#include "bbdd.h"
#include "bbdd-bfdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"

struct bbdd_br {
	struct bbdd_nl *nl;
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	struct bbdd_sock ctl;
	const char *bfddaddr;
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

static int bbdd_br_ctl_recv(struct bbdd_poll_ctx *, short, void *arg,
			    char **)
{
	struct bbdd_br *br = arg;

	bbdd_util_ctl_activity(&br->ctl, bbdd_br_handle_method, br);
	return 0;
}

static int bbdd_br_do_start(const char *addr, struct bbdd_mon_topics topics)
{
	struct bbdd_br br = { .bfddaddr = addr };
	char *error;
	int err = 0;

	br.nl = bbdd_nl_create();
	if (br.nl == NULL) {
		fprintf(stderr, "Failed to open netlink socket: %m\n");
		goto out;
	}

	br.pctx = bbdd_poll_init();
	if (br.pctx == NULL)
		goto nl_destroy;

	br.mon = bbdd_mon_init();
	if (br.mon == NULL) {
		fprintf(stderr, "Failed to create monitoring message bus: %m\n");
		goto poll_fini;
	}

	err = bbdd_mon_subscribe_cb(br.mon, bbdd_c_monitor_dispatch, NULL,
				    topics, &error);
	if (err != 0) {
		bbdd_util_printerr(&error, "Failed to subscribe to monitor");
		goto mon_fini;
	}

	err = bbdd_sock_open_d(&br.ctl, bbdd_env.sockdir);
	if (err != 0)
		goto mon_fini;

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
sock_close_d:
	bbdd_sock_close_d(&br.ctl);
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
