// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-sock.h"

#define BBDD_D_DEFAULT_DPLANEADDR "unix:/var/run/frr/bfdd_dplane.sock"

static void __bbdd_d_respond(struct bbdd_sock *ctl, struct json_object *obj)
{
	if (obj != NULL) {
		bbdd_jrpc_send(ctl, obj);
		json_object_put(obj);
	}
}

static void bbdd_d_respond_invalid_params(struct bbdd_sock *ctl,
					  struct json_object *id,
					  const char *data)
{
	__bbdd_d_respond(ctl, bbdd_jrpc_new_error_inv_params(id, data));
}

static void bbdd_d_respond_interr(struct bbdd_sock *peer,
				  struct json_object *id,
				  const char *data)
{
	__bbdd_d_respond(peer, bbdd_jrpc_new_error_int_error(id, data));
}

static void bbdd_d_respond_memerr(struct bbdd_sock *peer,
				  struct json_object *id)
{
	bbdd_d_respond_interr(peer, id, "Memory allocation issue");
}

static void bbdd_d_handle_ping(struct bbdd_sock *peer,
			       struct json_object *params_obj,
			       struct json_object *id)
{
	struct json_object *obj;
	int rc;

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	rc = json_object_object_add(obj, "result", params_obj);
	if (rc != 0)
		goto put_obj;
	json_object_get(params_obj);

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	bbdd_d_respond_memerr(peer, id);
}

static void bbdd_d_handle_stop(struct bbdd_sock *peer,
			       struct json_object *params_obj,
			       struct json_object *id)
{
	struct json_object *obj;
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	bfdd_request_terminate();

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (json_object_object_add(obj, "result", NULL))
		goto put_obj;

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	bbdd_d_respond_memerr(peer, id);
}

static void bbdd_d_handle_method(struct bbdd_sock *peer,
				 const char *method,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	if (strcmp(method, "stop") == 0) {
		bbdd_d_handle_stop(peer, params_obj, id);
		return;
	} else if (strcmp(method, "ping") == 0) {
		bbdd_d_handle_ping(peer, params_obj, id);
		return;
	}

	__bbdd_d_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_d_ctl_activity(struct bbdd_sock *ctl)
{
	struct json_object *request_obj;
	struct json_object *params;
	struct bbdd_sock peer;
	struct json_object *id;
	char *request = NULL;
	const char *method;
	char *error;
	int err;

	err = bbdd_sock_recv(ctl, &peer, &request);
	if (err < 0)
		return;

	request_obj = json_tokener_parse(request);
	if (request_obj == NULL) {
		__bbdd_d_respond(&peer,
				 bbdd_jrpc_new_error_inv_request(NULL));
		goto free_req;
	}

	err = bbdd_jrpc_dissect_request(request_obj, &id, &method, &params,
					&error);
	if (err) {
		__bbdd_d_respond(&peer,
				 bbdd_jrpc_new_error_inv_request(error));
		free(error);
		goto put_req_obj;
	}

	bbdd_d_handle_method(&peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
}

static void bbdd_d_ctl_recv(struct events_ctx *ec,
			    __attribute__((unused)) int sock,
			    short revents, void *arg)
{
	struct bbdd_sock *ctl = arg;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		bfddp_errx(1, "poll returned bad value");

	bbdd_d_ctl_activity(ctl);

	events_ctx_add_fd(ec, sock, POLLIN, bbdd_d_ctl_recv, arg);
}

static int bbdd_d_do_start(struct bbdd_sockaddr *dplane_sa)
{
	struct events_ctx *ec;
	struct bbdd_sock ctl;
	int err;

	openlog("bbdd", LOG_PID | LOG_CONS, LOG_USER);

	ec = events_ctx_new(64);
	if (ec == NULL) {
		fprintf(stderr, "Failed to create event context: %m\n");
		goto closelog;
	}

	err = bbdd_sock_open_d(&ctl, bbdd_env.sockdir);
	if (err)
		goto ctx_free;

	events_ctx_add_fd(ec, ctl.fd, POLLIN, bbdd_d_ctl_recv, &ctl);

	err = bfddp_start(ec, dplane_sa);

	bbdd_sock_close_d(&ctl);
ctx_free:
	events_ctx_free(&ec);
closelog:
	closelog();
	return err;
}

static void bbdd_d_start_help(void)
{
	fprintf(stderr,
		"Usage: bbdd start [dplaneaddr TYPE:ADDRESS[:PORT]]\n"
		"TYPE ::= {ipv4 | ipv6 | unix}\n"
		"Default dplaneaddr is `%s'.\n",
		BBDD_D_DEFAULT_DPLANEADDR);
}

int bbdd_d_start(int argc, char **argv)
{
	const char *dplaneaddr = BBDD_D_DEFAULT_DPLANEADDR;
	struct bbdd_sockaddr dplane_sa = {};
	int err;

	while (argc > 0) {
		if (strcmp(*argv, "help") == 0) {
			bbdd_d_start_help();
			return 0;

		} else if (strcmp(*argv, "dplaneaddr") == 0) {
			NEXT_ARG();
			dplaneaddr = *argv;
			NEXT_ARG_FWD();

		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			return -1;
		}
		continue;

incomplete_command:
		fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
		return -1;
	}

	err = bbdd_sock_parse_addr(dplaneaddr, &dplane_sa);
	if (err)
		return -1;

	return bbdd_d_do_start(&dplane_sa);
}
