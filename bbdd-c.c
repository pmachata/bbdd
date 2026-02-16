// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/linkhash.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-sock.h"

static bool bbdd_c_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id;

	id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void bbdd_c_response_handle_error(struct json_object *error_obj)
{
	struct json_object *data;
	const char *message;
	int64_t code;
	char *error;
	int err;

	err = bbdd_jrpc_dissect_error(error_obj, &code, &message, &data,
				      &error);
	if (err != 0) {
		fprintf(stderr, "Invalid error object: %s\n", error);
		free(error);
		return;
	}

	if (data != NULL)
		fprintf(stderr, "Error %" PRId64 ": %s (%s)\n", code, message,
			json_object_to_json_string(data));
	else
		fprintf(stderr, "Error %" PRId64 ": %s\n", code, message);
}

static bool bbdd_c_response_extract_result(struct json_object *j,
					   int expect_id,
					   enum json_type result_type,
					   struct json_object **ret_result)
{
	struct json_object *result;
	struct json_object *id;
	bool is_error;
	char *error;
	int err;

	err = bbdd_jrpc_dissect_response(j, &id, &result, &is_error, &error);
	if (err) {
		fprintf(stderr, "Invalid response object: %s\n", error);
		free(error);
		return false;
	}

	if (!bbdd_c_validate_id(id, expect_id)) {
		fprintf(stderr, "Unknown response ID: %s\n",
			json_object_to_json_string(id));
		return false;
	}

	if (is_error) {
		bbdd_c_response_handle_error(result);
		return false;
	}

	if (json_object_get_type(result) != result_type) {
		fprintf(stderr, "Unexpected result type: %s expected, got %s\n",
			json_type_to_name(result_type),
			json_type_to_name(json_object_get_type(result)));
		return false;
	}

	*ret_result = json_object_get(result);
	return true;
}

static bool __bbdd_c_result_show_json(struct json_object *result)
{
	const char *dump;

	if (bbdd_env.show_json) {
		dump = json_object_to_json_string(result);
		fprintf(stdout, "%s", dump);
		return true;
	}

	return false;
}

static bool bbdd_c_result_show_json(struct json_object *result)
{
    bool ret = __bbdd_c_result_show_json(result);

	if (ret)
		putchar('\n');
	return ret;
}

static struct json_object *bbdd_c_send_request_on(struct json_object *request,
						  struct bbdd_sock *cli,
						  struct bbdd_sock *peer)
{
	struct json_object *response_obj = NULL;
	char *response;
	int err;

	err = bbdd_jrpc_send(peer, request);
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		return NULL;
	}

	err = bbdd_sock_recv(cli, peer, &response);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		return NULL;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		fprintf(stderr, "Failed to parse RPC response as JSON.\n");
		goto free_response;
	}

free_response:
	free(response);
	return response_obj;
}

static struct json_object *bbdd_c_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	struct bbdd_sock peer;
	struct bbdd_sock cli;
	int err;

	err = bbdd_sock_open_c(&cli, &peer, bbdd_env.sockdir);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return NULL;
	}

	response_obj = bbdd_c_send_request_on(request, &cli, &peer);

	bbdd_sock_close_c(&cli);
	return response_obj;
}

static int bbdd_c_cmd_noargs(int argc, char **argv, void (*help_cb)(void))
{
	while (argc > 0) {
		if (strcmp(*argv, "help") == 0) {
			help_cb();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			return -1;
		}
	}

	return 0;
}

static void bbdd_c_ping_help(void)
{
	fprintf(stderr,
		"Usage: bbdd ping\n"
		"\n"
	);
}

static int bbdd_c_ping_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;
	int nr;
	int rc;
	int r;

	request = bbdd_jrpc_new_request(id, "ping");
	if (request == NULL)
		return -1;

	srand((unsigned int)time(NULL));
	r = rand();
	rc = bbdd_jrpc_object_add_int(request, "params", r);
	if (rc != 0) {
		fprintf(stderr, "Failed to form a request object.\n");
		err = -1;
		goto put_request;
	}

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!bbdd_c_response_extract_result(response, id, json_type_int,
					    &result)) {
		err = -1;
		goto put_response;
	}

	if (bbdd_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	nr = json_object_get_int(result);
	if (nr != r) {
		fprintf(stderr, "Unexpected ping response: sent %d, got %d.\n",
			r, nr);
		err = -1;
		goto put_result;
	}

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bbdd is alive\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int bbdd_c_ping(int argc, char **argv)
{
	int err;

	err = bbdd_c_cmd_noargs(argc, argv, bbdd_c_ping_help);
	if (err != 0)
		return err;

	return bbdd_c_ping_jrpc();
}

static void bbdd_c_stop_help(void)
{
	fprintf(stderr,
		"Usage: bbdd stop\n"
		"\n"
	);
}

static int bbdd_c_stop_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	request = bbdd_jrpc_new_request(id, "stop");
	if (request == NULL)
		return -1;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!bbdd_c_response_extract_result(response, id, json_type_null,
					    &result)) {
		err = -1;
		goto put_response;
	}

	if (bbdd_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bbdd will stop\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int bbdd_c_stop(int argc, char **argv)
{
	int err;

	err = bbdd_c_cmd_noargs(argc, argv, bbdd_c_stop_help);
	if (err != 0)
		return err;

	return bbdd_c_stop_jrpc();
}

enum bbdd_c_session_command {
	bbdd_c_session_command_add,
};

static int bbdd_c_session_help(void)
{
	fprintf(stderr,
		"Usage:	bbdd session { add } PARAMS\n"
		"where	PARAMS := PARAM [ PARAMS ]\n"
		"	PARAM := { KEY VALUE | FLAG }\n"
		"	KEY := { lid | src | dst | min-tx | min-rx | min-echo-tx | min-echo-rx | hold-time | ttl | detect-mult | ifname | ifindex }\n"
		"	FLAG := { multihop | demand | cbit | echo | ipv6 | passive | shutdown }\n"
		"\n"
		"Parameter KEY and VALUE details:\n"
		"	lid U32 	-- session ID\n"
		"	src ADDR	-- source address\n"
		"	dst ADDR	-- destination address\n"
		"	min-tx U32	-- minimum tx interval in microseconds\n"
		"	min-rx U32	-- minimum rx interval in microseconds\n"
		"	min-echo-tx U32	-- minimum tx echo interval in microseconds\n"
		"	min-echo-rx U32	-- minimum rx echo interval in microseconds\n"
		"	hold-time U32	-- session start wait time in miliseconds\n"
		"	ttl U8		-- minimum packet TTL\n"
		"	detect-mult U8	-- detection multiplier\n"
		"	ifname STR	-- interface name\n"
		"	ifindex U32	-- interface index\n"
		"\n"
		"where	U8 := 8-bit numerical value (0..255)\n"
		"	U32 := 32-bit numerical value (0..4Gi)\n"
		"	STR := a string value\n"
		"	ADDR := an IPv4 or IPv6 network address\n"
		"\n"
		"FLAG details:\n"
		"	multihop	-- multi-hop session\n"
		"	demand		-- demand mode\n"
		"	cbit		-- control-plane independent\n"
		"	echo		-- echo mode\n"
		"	ipv6		-- session is running over IPv6\n"
		"	passive		-- passive mode\n"
		"	shutdown	-- session is admin down\n"
	);
	return 0;
}

static int
bbdd_c_parse_kw(int *up_argc, char ***up_argv,
		const char *kw, void *ret, int *ret_seen,
		int (*parser)(const char *arg, void *ret, const char *kw))
{
	int argc = *up_argc;
	char **argv = *up_argv;
	int rc;

	if (strcmp(*argv, kw) != 0)
		return 0;

	if (*ret_seen != 0) {
		fprintf(stderr, "Duplicate keyword `%s'.\n", kw);
		return -1;
	}

	if (parser != NULL) {
		NEXT_ARG();

		rc = parser(*argv, ret, kw);
		if (rc < 0)
			return rc;
		if (rc == 0)
			rc = 1;
	} else {
		rc = 1;
	}

	NEXT_ARG_FWD();

	*ret_seen = rc;
	*up_argc = argc;
	*up_argv = argv;
	return 1;

incomplete_command:
	fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
	return -1;
}

static int bbdd_c_parse_u8(const char *str, void *ret, const char *what)
{
	uint8_t *u8_ret = ret;
	return bbdd_sock_parse_u8(str, u8_ret, what);
}

static int bbdd_c_parse_u32(const char *str, void *ret, const char *what)
{
	uint32_t *u32_ret = ret;
	return bbdd_sock_parse_u32(str, u32_ret, what);
}

static int bbdd_c_parse_str(const char *str, void *ret, const char *)
{
	const char **ret_str = ret;
	*ret_str = str;
	return 0;
}

static int bbdd_c_parse_addr(const char *str, void *ret, const char *what)
{
	const char **ret_str = ret;
	union {
		uint32_t ipv4;
		struct in6_addr ipv6;
	} u;

	*ret_str = str;
	if (inet_pton(AF_INET, str, &u.ipv4) == 1)
		return AF_INET;
	else if (inet_pton(AF_INET6, str, &u.ipv6) == 1)
		return AF_INET6;

	fprintf(stderr, "Can't parse %s `%s' as either IPv4 or IPv6 address.\n",
		what, str);
	return -1;
}

static int bbdd_c_parse_kw_u8(int *up_argc, char ***up_argv, const char *kw,
			      uint8_t *ret, int *ret_seen)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_seen,
			       bbdd_c_parse_u8);
}

static int bbdd_c_parse_kw_u32(int *up_argc, char ***up_argv, const char *kw,
			       uint32_t *ret, int *ret_seen)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_seen,
			       bbdd_c_parse_u32);
}

static int bbdd_c_parse_kw_str(int *up_argc, char ***up_argv, const char *kw,
			       const char **ret, int *ret_seen)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_seen,
			       bbdd_c_parse_str);
}

static int bbdd_c_parse_kw_addr(int *up_argc, char ***up_argv, const char *kw,
				const char **ret, int *ret_af)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_af,
			       bbdd_c_parse_addr);
}

static int bbdd_c_parse_kw_flag(int *up_argc, char ***up_argv,
				const char *kw, bool *flag)
{
	int seen = *flag;
	int rc;

	rc = bbdd_c_parse_kw(up_argc, up_argv, kw, flag, &seen,
			     NULL);
	if (rc > 0)
		*flag = true;
	return rc;
}

struct bbdd_c_session {
	/* Flags. */
	bool multihop;
	bool demand;
	bool cbit;
	bool echo;
	bool ipv6;
	bool passive;
	bool shutdown;
	/* Other fields. */
	const char *src;		int src_af;
	const char *dst;		int dst_af;
	uint32_t lid;			int lid_seen;
	uint32_t min_tx;		int min_tx_seen;
	uint32_t min_rx;		int min_rx_seen;
	uint32_t min_echo_tx;		int min_echo_tx_seen;
	uint32_t min_echo_rx;		int min_echo_rx_seen;
	uint32_t hold_time;		int hold_time_seen;
	uint8_t ttl;			int ttl_seen;
	uint8_t detect_mult;		int detect_mult_seen;
	uint32_t ifindex;		int ifindex_seen;
	const char *ifname;		int ifname_seen;
};

static int bbdd_c_session_jrpc(enum bbdd_c_session_command scmd,
			       struct bbdd_c_session *sess)
{
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const char *method;
	const int id = 1;
	int err;

	switch (scmd) {
	case bbdd_c_session_command_add:
		method = "session-add";
		break;
	}

	request = bbdd_jrpc_new_request(id, method);
	if (request == NULL)
		return -1;

	params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = -ENOMEM;
		goto put_request;
	}

	if ((sess->src_af &&
	     bbdd_jrpc_append_str(params_obj, "src", sess->src)) ||
	    (sess->dst_af &&
	     bbdd_jrpc_append_str(params_obj, "dst", sess->dst)) ||
	    (sess->lid_seen &&
	     bbdd_jrpc_append_int(params_obj, "lid", sess->lid)) ||
	    (sess->min_tx_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_tx", sess->min_tx)) ||
	    (sess->min_rx_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_rx", sess->min_rx)) ||
	    (sess->min_echo_tx_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_echo_tx",
				  sess->min_echo_tx)) ||
	    (sess->min_echo_rx_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_echo_rx",
				  sess->min_echo_rx)) ||
	    (sess->hold_time_seen &&
	     bbdd_jrpc_append_int(params_obj, "hold_time", sess->hold_time)) ||
	    (sess->ttl_seen &&
	     bbdd_jrpc_append_int(params_obj, "ttl", sess->ttl)) ||
	    (sess->detect_mult_seen &&
	     bbdd_jrpc_append_int(params_obj, "detect_mult",
				  sess->detect_mult)) ||
	    (sess->ifindex_seen &&
	     bbdd_jrpc_append_int(params_obj, "ifindex", sess->ifindex)) ||
	    (sess->ifname_seen &&
	     bbdd_jrpc_append_str(params_obj, "ifname", sess->ifname)))
		goto put_params_obj;

	// xxx flags

	if (json_object_object_add(request, "params", params_obj)) {
		err = -ENOMEM;
		goto put_params_obj;
	}
	params_obj = NULL;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!bbdd_c_response_extract_result(response, id, json_type_null,
					    &result)) {
		err = -1;
		goto put_response;
	}

	if (bbdd_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "xxx sent session-add & got response\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return err;
}

static int bbdd_c_session_command(enum bbdd_c_session_command scmd,
				  int argc, char **argv)
{
	struct bbdd_c_session sess = {};
	int rc;

	while (argc > 0) {
		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "multihop",
					       &sess.multihop)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "demand",
					       &sess.demand)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "cbit",
					       &sess.cbit)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "echo",
					       &sess.echo)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "ipv6",
					       &sess.ipv6)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "passive",
					       &sess.passive)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "shutdown",
					       &sess.shutdown)) ||

		    (rc = bbdd_c_parse_kw_addr(&argc, &argv, "src",
					       &sess.src,
					       &sess.src_af)) ||
		    (rc = bbdd_c_parse_kw_addr(&argc, &argv, "dst",
					       &sess.dst,
					       &sess.dst_af)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "lid",
					      &sess.lid,
					      &sess.lid_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-tx",
					      &sess.min_tx,
					      &sess.min_tx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-rx",
					      &sess.min_rx,
					      &sess.min_rx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-echo-tx",
					      &sess.min_echo_tx,
					      &sess.min_echo_tx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-echo-rx",
					      &sess.min_echo_rx,
					      &sess.min_echo_rx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "hold-time",
					      &sess.hold_time,
					      &sess.hold_time_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "ttl",
					     &sess.ttl,
					     &sess.ttl_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "detect-mult",
					     &sess.detect_mult,
					     &sess.detect_mult_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "ifindex",
					      &sess.ifindex,
					      &sess.ifindex_seen)) ||
		    (rc = bbdd_c_parse_kw_str(&argc, &argv, "ifname",
					      &sess.ifname,
					      &sess.ifname_seen))) {
			if (rc > 0)
				continue;
			return rc;
		}

		if (strcmp(*argv, "help") == 0)
			return bbdd_c_session_help();

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	if (sess.src_af != 0 && sess.dst_af != 0 &&
	    sess.src_af != sess.dst_af) {
		fprintf(stderr, "src and dst are given from different protocols: `%s' (%s) vs. `%s' (%s).\n",
			sess.src, sess.src_af == AF_INET ? "IPv4" : "IPv6",
			sess.dst, sess.dst_af == AF_INET ? "IPv4" : "IPv6");
		return -1;
	}
	if ((sess.src_af == AF_INET || sess.dst_af == AF_INET) && sess.ipv6) {
		fprintf(stderr, "src or dst given as IPv4, but `ipv6' flag given as well.\n");
		return -1;
	}
	if (sess.src_af == AF_INET6 || sess.dst_af == AF_INET6)
		sess.ipv6 = true;

	// xxx check ifindex vs. ifname if both given. If one is given, deduce
	// one from the other.

	return bbdd_c_session_jrpc(scmd, &sess);
}

int bbdd_c_session(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		return bbdd_c_session_help();
	} else if (strcmp(*argv, "add") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_session_command(bbdd_c_session_command_add,
					      argc, argv);
	}

	fprintf(stderr, "What is \"%s\"?\n", *argv);
	return -1;
}
