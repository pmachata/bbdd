// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
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
#include <json-c/json_util.h>

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

static void bbdd_d_handle_ping(struct events_ctx *,
			       struct bfddp_ctx *,
			       struct bbdd_sock *peer,
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

static void bbdd_d_respond_empty(struct bbdd_sock *peer, struct json_object *id)
{
	struct json_object *obj;

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

static void bbdd_d_handle_stop(__attribute__((unused)) struct events_ctx *ec,
			       __attribute__((unused)) struct bfddp_ctx *bctx,
			       struct bbdd_sock *peer,
			       struct json_object *params_obj,
			       struct json_object *id)
{
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	bfdd_request_terminate();
	bbdd_d_respond_empty(peer, id);
}

static int bbdd_d_jrpc_dissect_session_flags(struct json_object *flag_array,
					     uint32_t *pflags,
					     char **error)
{
	static struct {
		const char *name;
		uint32_t value;
	} flag_strs[] = {
		{"multihop", SESSION_MULTIHOP},
		{"demand",   SESSION_DEMAND},
		{"cbit",     SESSION_CBIT},
		{"echo",     SESSION_ECHO},
		{"ipv6",     SESSION_IPV6},
		{"passive",  SESSION_PASSIVE},
		{"shutdown", SESSION_SHUTDOWN},
	};
	size_t flag_array_len;

	assert(json_object_get_type(flag_array) == json_type_array);
	flag_array_len = json_object_array_length(flag_array);

	*pflags = 0;
	for (size_t i = 0; i < flag_array_len; i++) {
		struct json_object *flag_obj =
			json_object_array_get_idx(flag_array, i);
		enum json_type type = json_object_get_type(flag_obj);
		const char *str;

		if (type != json_type_string) {
			bbdd_jrpc_fmterr(error, "Session flag array element expected to be string, got %s",
					 json_type_to_name(type));
			return -1;
		}

		str = json_object_get_string(flag_obj);
		for (size_t j = 0; j < ARRAY_SIZE(flag_strs); j++)
			if (strcmp(flag_strs[j].name, str) == 0) {
				*pflags |= flag_strs[j].value;
				goto next;
			}
		bbdd_jrpc_fmterr(error, "Unknown session flag `%s'", str);
		return -1;
	next:
	}

	return 0;
}

static int bbdd_d_jrpc_dissect_address(struct json_object *addr_obj,
				       uint32_t flags,
				       struct in6_addr *ret_addr,
				       char **error)
{
	int af = flags & SESSION_IPV6 ? AF_INET6 : AF_INET;
	const char *addr_str;

	assert(json_object_get_type(addr_obj) == json_type_string);
	addr_str = json_object_get_string(addr_obj);
	return bbdd_inet_pton(af, addr_str, ret_addr, error);
}

int bbdd_d_jrpc_dissect_params_session(struct json_object *obj,
				       struct bfddp_session *sess,
				       char **error)
{
	enum {
		pol_lid,
		pol_flags,

		pol_src,
		pol_dst,

		pol_min_tx,
		pol_min_rx,
		pol_min_echo_tx,
		pol_min_echo_rx,

		pol_hold_time,
		pol_ttl,
		pol_detect_mult,

		pol_ifindex,
		pol_ifname,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_lid] =  { .key = "lid", .type = json_type_int },
		[pol_flags] = { .key = "flags", .type = json_type_array },

		[pol_src] = { .key = "src", .type = json_type_string },
		[pol_dst] = { .key = "dst", .type = json_type_string },

		[pol_min_tx] = { .key = "min_tx", .type = json_type_int },
		[pol_min_rx] = { .key = "min_rx", .type = json_type_int },
		[pol_min_echo_tx] = { .key = "min_echo_tx",
				      .type = json_type_int },
		[pol_min_echo_rx] = { .key = "min_echo_rx",
				      .type = json_type_int },

		[pol_hold_time] = { .key = "hold_time", .type = json_type_int },
		[pol_ttl] = { .key = "ttl", .type = json_type_int },
		[pol_detect_mult] = { .key = "detect_mult",
				      .type = json_type_int },

		[pol_ifindex] = { .key = "ifindex", .type = json_type_int },
		[pol_ifname] = { .key = "ifname", .type = json_type_string },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	memset(sess, 0, sizeof(*sess));

	if ((seen[pol_lid] &&
	     bbdd_jrpc_get_uint32_non0(values[pol_lid],
				       &sess->lid, error) < 0) ||
	    (seen[pol_flags] &&
	     bbdd_d_jrpc_dissect_session_flags(values[pol_flags],
					       &sess->flags, error) < 0) ||
	    (seen[pol_src] &&
	     bbdd_d_jrpc_dissect_address(values[pol_src], sess->flags,
					 &sess->src, error) < 0) ||
	    (seen[pol_dst] &&
	     bbdd_d_jrpc_dissect_address(values[pol_src], sess->flags,
					 &sess->dst, error) < 0) ||
	    (seen[pol_min_tx] &&
	     bbdd_jrpc_get_uint32_non0(values[pol_min_tx],
				       &sess->min_tx, error) < 0) ||
	    (seen[pol_min_rx] &&
	     bbdd_jrpc_get_uint32_non0(values[pol_min_rx],
				       &sess->min_rx, error) < 0) ||
	    (seen[pol_min_echo_tx] &&
	     bbdd_jrpc_get_uint32(values[pol_min_echo_tx],
				  &sess->min_echo_tx, error) < 0) ||
	    (seen[pol_min_echo_rx] &&
	     bbdd_jrpc_get_uint32(values[pol_min_echo_rx],
				  &sess->min_echo_rx, error) < 0) ||
	    (seen[pol_hold_time] &&
	     bbdd_jrpc_get_uint32(values[pol_hold_time], &sess->hold_time,
				  error) < 0) ||
	    (seen[pol_ttl] &&
	     bbdd_jrpc_get_uint8(values[pol_ttl], &sess->ttl, error) < 0) ||
	    (seen[pol_detect_mult] &&
	     bbdd_jrpc_get_uint8(values[pol_detect_mult], &sess->detect_mult,
				 error) < 0) ||
	    (seen[pol_ifindex] &&
	     bbdd_jrpc_get_uint32_non0(values[pol_ifindex], &sess->ifindex,
				       error) < 0) ||
	    (seen[pol_ifname] &&
	     bbdd_jrpc_strcpy(values[pol_ifname],
			      sess->ifname, sizeof sess->ifname, error) < 0))
		return -1;

#define HTONL_FIELD(FIELD) FIELD = htonl(FIELD)
	HTONL_FIELD(sess->lid);
	HTONL_FIELD(sess->flags);
	HTONL_FIELD(sess->min_tx);
	HTONL_FIELD(sess->min_rx);
	HTONL_FIELD(sess->min_echo_rx);
	HTONL_FIELD(sess->min_echo_tx);
	HTONL_FIELD(sess->hold_time);
	HTONL_FIELD(sess->ifindex);
#undef HTONL_FIELD

	return 0;
}

static void bbdd_d_handle_session_list(struct events_ctx *,
				       struct bfddp_ctx *,
				       struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	struct json_object *obj;
	struct json_object *result_obj;
	struct bfd_session *bs = NULL;
	struct json_object *array;
	struct json_object *sess_obj;
	char *error;
	int rc;

	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "sessions": [ SESS, ... ]
	 *     }
	 * }
	 *
	 * Where individual SESS objects are formatted the same as session
	 * request objects, see bbdd_d_jrpc_dissect_params_session().
	 */

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	rc = json_object_object_add(obj, "result", params_obj);
	if (rc != 0)
		goto put_obj;
	json_object_get(params_obj);

	array = json_object_new_array();
	if (array == NULL)
		goto put_result_obj;

	while ((bs = bfd_sessions_walk(bs))) {
		struct bbdd_c_session sess = {
			.lid = bs->bs_lid,
			.lid_seen = true,
		};

		sess_obj = bbdd_c_jrpc_session_obj(&sess);
		if (sess_obj == NULL)
			goto put_array;

		if (json_object_array_add(array, sess_obj) != 0)
			goto put_sess_obj;
		sess_obj = NULL;
	}

	rc = json_object_object_add(result_obj, "sessions", array);
	if (rc != 0)
		goto put_array;
	array = NULL;

	if (json_object_object_add(obj, "result", result_obj))
		goto put_result_obj;

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_sess_obj:
	json_object_put(sess_obj);
put_array:
	json_object_put(array);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	bbdd_d_respond_memerr(peer, id);
}

static void bbdd_d_handle_session_add(struct events_ctx *ec,
				      struct bfddp_ctx *bctx,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bfddp_session sess;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, &sess, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	bfddp_process_edit_session(ec, bctx, &sess);
	bbdd_d_respond_empty(peer, id);
}

static void bbdd_d_handle_method(struct events_ctx *ec,
				 struct bfddp_ctx *bctx,
				 struct bbdd_sock *peer,
				 const char *method,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct bbdd_d_method_handler {
		const char *method;
		void (*handler)(struct events_ctx *ec,
				struct bfddp_ctx *bctx,
				struct bbdd_sock *peer,
				struct json_object *params_obj,
				struct json_object *id);
	};
	static struct bbdd_d_method_handler handlers[] = {
		{"stop", bbdd_d_handle_stop},
		{"ping", bbdd_d_handle_ping},
		{"session-list", bbdd_d_handle_session_list},
		{"session-add", bbdd_d_handle_session_add},
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (strcmp(method, handlers[i].method) == 0)
			return handlers[i].handler(ec, bctx, peer,
						   params_obj, id);

	__bbdd_d_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_d_ctl_activity(struct events_ctx *ec,
				struct bfddp_ctx *bctx,
				struct bbdd_sock *ctl)
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

	bbdd_d_handle_method(ec, bctx, &peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
}

struct bbdd_context {
	struct bfddp_ctx *bctx;
	struct bbdd_sock ctl;
};

static void bbdd_d_ctl_recv(struct events_ctx *ec,
			    __attribute__((unused)) int sock,
			    short revents, void *arg)
{
	struct bbdd_context *bbdd = arg;
	struct bfddp_ctx *bctx = bbdd->bctx;
	struct bbdd_sock *ctl = &bbdd->ctl;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		bfddp_errx(1, "poll returned bad value");

	bbdd_d_ctl_activity(ec, bctx, ctl);

	events_ctx_add_fd(ec, sock, POLLIN, bbdd_d_ctl_recv, arg);
}

static int bbdd_d_do_start(struct bbdd_sockaddr *dplane_sa)
{
	struct bbdd_context bbdd;
	struct events_ctx *ec;
	int err;

	openlog("bbdd", LOG_PID | LOG_CONS, LOG_USER);

	bbdd.bctx = bfddp_new(0, 0);
	if (bbdd.bctx == NULL) {
		fprintf(stderr, "Failed to create BFDdp context: %m\n");
		goto closelog;
	}

	ec = events_ctx_new(64);
	if (ec == NULL) {
		fprintf(stderr, "Failed to create event context: %m\n");
		goto bfddp_free;
	}

	err = bbdd_sock_open_d(&bbdd.ctl, bbdd_env.sockdir);
	if (err)
		goto ctx_free;

	events_ctx_add_fd(ec, bbdd.ctl.fd, POLLIN, bbdd_d_ctl_recv, &bbdd);

	err = bfddp_start(bbdd.bctx, ec, dplane_sa);

	bbdd_sock_close_d(&bbdd.ctl);
ctx_free:
	events_ctx_free(&ec);
bfddp_free:
	bfddp_free(bbdd.bctx);
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
