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
	bbdd_c_session_command_set,
	bbdd_c_session_command_del,
};

static void bbdd_c_session_help(void)
{
	fprintf(stderr,
		"Usage:	bbdd session add [ SET-PARAMS ]\n"
		"	bbdd session [ QUERY-PARAMS ] [bulk] set [ SET-PARAMS ]\n"
		"	bbdd session [ QUERY-PARAMS ] [bulk] del\n"
		"	bbdd session list\n"
		"\n"
		"where	QUERY-PARAMS := PARAMS	-- parameters for session select\n"
		"	SET-PARAMS := PARAMS	-- adjusted / new session parameters\n"
		"	PARAMS ::= PARAM [ PARAMS ]\n"
		"	PARAM ::= { KEY VALUE | [ no ] FLAG }\n"
		"	KEY ::= { lid | src | dst | min-tx | min-rx | min-echo-tx | min-echo-rx | hold-time | ttl | detect-mult | ifname | ifindex }\n"
		"	FLAG ::= { multihop | demand | cbit | echo | ipv6 | passive | shutdown }\n"
		"       bulk		-- set & del requests are allowed to impact >1 session\n"
		"	no FLAG		-- set the flag to negative value"
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

static int
bbdd_c_parse_kw_flag(int *up_argc, char ***up_argv,
		     const char *kw, struct bbdd_c_session_flag *flag)
{
	int argc = *up_argc;
	char **argv = *up_argv;
	bool value = true;

	if (strcmp(*argv, "no") == 0) {
		value = false;
		NEXT_ARG();
	}

	if (strcmp(*argv, kw) != 0)
		return 0;

	if (flag->seen) {
		fprintf(stderr, "Duplicate keyword `%s%s'.\n",
			value ? "" : "no ", kw);
		return -1;
	}

	NEXT_ARG_FWD();

	flag->value = value;
	flag->seen = true;
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

static int __bbdd_c_parse_ifname(const char *str, char ret_str[IFNAMSIZ],
				 const char *what)
{
	if (strlen(str) >= IFNAMSIZ) {
		fprintf(stderr, "Can't parse %s `%s': too long.\n",
			what, str);
		return -1;
	}
	strcpy(ret_str, str);
	return 0;
}

static int bbdd_c_parse_ifname(const char *str, void *ret, const char *what)
{
	return __bbdd_c_parse_ifname(str, ret, what);
}

static int __bbdd_c_parse_addr(const char *str, char ret_str[INET6_ADDRSTRLEN],
			       const char *what)
{
	union {
		uint32_t ipv4;
		struct in6_addr ipv6;
	} u;

	if (strlen(str) >= INET6_ADDRSTRLEN) {
		fprintf(stderr, "Can't parse %s `%s': address too long.\n",
			what, str);
		return -1;
	}
	strcpy(ret_str, str);

	if (inet_pton(AF_INET, str, &u.ipv4) == 1)
		return AF_INET;
	else if (inet_pton(AF_INET6, str, &u.ipv6) == 1)
		return AF_INET6;

	fprintf(stderr, "Can't parse %s `%s' as either IPv4 or IPv6 address.\n",
		what, str);
	return -1;
}

static int bbdd_c_parse_addr(const char *str, void *ret, const char *what)
{
	return __bbdd_c_parse_addr(str, ret, what);
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

static int bbdd_c_parse_kw_ifname(int *up_argc, char ***up_argv, const char *kw,
				  char ret[IFNAMSIZ], int *ret_seen)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_seen,
			       bbdd_c_parse_ifname);
}

static int bbdd_c_parse_kw_addr(int *up_argc, char ***up_argv, const char *kw,
				char ret[INET6_ADDRSTRLEN], int *ret_af)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_af,
			       bbdd_c_parse_addr);
}

#define BBDD_C_SESSION_EXPAND_NAME_STR(NAME, name, ...)	#name,
static const char *bbdd_c_session_flag_names[] = {
	BBDD_C_SESSION_FLAGS(BBDD_C_SESSION_EXPAND_NAME_STR)
};
#undef BBDD_C_SESSION_EXPAND_NAME_STR

const char *
bbdd_c_session_flag_name(enum bbdd_c_session_flag_ix flag)
{
	return bbdd_c_session_flag_names[flag];
}

struct json_object *bbdd_c_jrpc_session_obj(struct bbdd_c_session *sess)
{
	struct json_object *params_obj;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		return NULL;

	for (int i = 0; i < bbdd_c_session_nflags; i++) {
		const char *flag_name = bbdd_c_session_flag_names[i];
		struct bbdd_c_session_flag *flag = &sess->flags.flags[i];

		if (!flag->seen)
			continue;

		if (bbdd_jrpc_append_bool(params_obj, flag_name, flag->value))
			goto put_params_obj;
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
	     bbdd_jrpc_append_str(params_obj, "ifname", sess->ifname)) ||

	    (sess->bulk &&
	     bbdd_jrpc_append_bool(params_obj, "bulk", sess->bulk)))
		goto put_params_obj;

	return params_obj;

put_params_obj:
	json_object_put(params_obj);
	return NULL;
}

static int bbdd_c_session_jrpc(enum bbdd_c_session_command command,
			       struct bbdd_c_session *select,
			       struct bbdd_c_session *change)
{
	struct json_object *select_obj;
	struct json_object *change_obj;
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const char *method;
	const int id = 1;
	int err;

	// xxx seems like errors here are not reported in any way to the user

	switch (command) {
	case bbdd_c_session_command_add:
		method = "session-add";
		select_obj = NULL;
		change_obj = bbdd_c_jrpc_session_obj(change);
		if (change_obj == NULL)
			return -1;
		break;

	case bbdd_c_session_command_set:
		method = "session-set";
		select_obj = bbdd_c_jrpc_session_obj(select);
		if (select_obj == NULL)
			return -1;
		change_obj = bbdd_c_jrpc_session_obj(change);
		if (change_obj == NULL) {
			err = -ENOMEM;
			goto put_select;
		}
		break;

	case bbdd_c_session_command_del:
		method = "session-del";
		select_obj = bbdd_c_jrpc_session_obj(select);
		change_obj = NULL;
		if (select_obj == NULL)
			return -1;
		break;
	}

	request = bbdd_jrpc_new_request(id, method);
	if (request == NULL) {
		err = -ENOMEM;
		goto put_select_change;
	}

	params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = -ENOMEM;
		goto put_request;
	}

	if (select_obj != NULL &&
	    json_object_object_add(params_obj, "select", select_obj)) {
		err = -ENOMEM;
		goto put_params_obj;
	}
	select_obj = NULL;

	if (change_obj != NULL &&
	    json_object_object_add(params_obj, "change", change_obj)) {
		err = -ENOMEM;
		goto put_params_obj;
	}
	change_obj = NULL;

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
		fprintf(stderr, "xxx sent %s & got response\n", method);
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
put_select_change:
	json_object_put(change_obj);
put_select:
	json_object_put(select_obj);
	return err;
}

static int bbdd_c_session_check_params(struct bbdd_c_session *sess)
{
	if (sess->src_af != 0 && sess->dst_af != 0 &&
	    sess->src_af != sess->dst_af) {
		fprintf(stderr, "src and dst are given from different protocols: `%s' (%s) vs. `%s' (%s).\n",
			sess->src, sess->src_af == AF_INET ? "IPv4" : "IPv6",
			sess->dst, sess->dst_af == AF_INET ? "IPv4" : "IPv6");
		return -1;
	}
	if ((sess->src_af == AF_INET || sess->dst_af == AF_INET) &&
	    sess->flags.ipv6.seen && sess->flags.ipv6.value) {
		fprintf(stderr, "src or dst given as IPv4, but `ipv6' flag given as well.\n");
		return -1;
	}
	if (sess->src_af == AF_INET6 || sess->dst_af == AF_INET6) {
		sess->flags.ipv6.seen = true;
		sess->flags.ipv6.value = true;
	}

	// xxx check ifindex vs. ifname if both given. If one is given, deduce
	// one from the other.
	return 0;
}

static int bbdd_c_session_asd(int argc, char **argv)
{
	struct bbdd_c_session select = {};
	struct bbdd_c_session change = {};
	struct bbdd_c_session *sess = &select;
	bool seen_arg = false;
	bool seen_command = false;
	struct bbdd_c_session_flag bulk = {};
	enum bbdd_c_session_command command;
	int rc;

	while (argc > 0) {
		if (strcmp(*argv, "add") == 0) {
			if (seen_command) {
			seen_command:
				fprintf(stderr, "`%s' seen when a command was already given\n",
					*argv);
				return -1;
			}
			if (seen_arg) {
				fprintf(stderr, "`add' used with session query parameters\n");
				return -1;
			}
			NEXT_ARG_FWD();
			command = bbdd_c_session_command_add;
			seen_command = true;
			sess = &change;
			continue;

		} else if (strcmp(*argv, "set") == 0) {
			if (seen_command)
				goto seen_command;
			NEXT_ARG_FWD();
			command = bbdd_c_session_command_set;
			seen_command = true;
			sess = &change;
			continue;

		} else if (strcmp(*argv, "del") == 0) {
			if (seen_command)
				goto seen_command;
			NEXT_ARG_FWD();
			command = bbdd_c_session_command_del;
			seen_command = true;
			sess = NULL;
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			bbdd_c_session_help();
			return 0;
		}

		if (sess == NULL) {
			fprintf(stderr, "`del' used with session change parameters\n");
			return -1;
		}

		seen_arg = true;

		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "multihop",
					       &sess->flags.multihop)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "demand",
					       &sess->flags.demand)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "cbit",
					       &sess->flags.cbit)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "echo",
					       &sess->flags.echo)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "ipv6",
					       &sess->flags.ipv6)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "passive",
					       &sess->flags.passive)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "shutdown",
					       &sess->flags.shutdown)) ||

		    (rc = bbdd_c_parse_kw_addr(&argc, &argv, "src",
					       sess->src,
					       &sess->src_af)) ||
		    (rc = bbdd_c_parse_kw_addr(&argc, &argv, "dst",
					       sess->dst,
					       &sess->dst_af)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "lid",
					      &sess->lid,
					      &sess->lid_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-tx",
					      &sess->min_tx,
					      &sess->min_tx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-rx",
					      &sess->min_rx,
					      &sess->min_rx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-echo-tx",
					      &sess->min_echo_tx,
					      &sess->min_echo_tx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "min-echo-rx",
					      &sess->min_echo_rx,
					      &sess->min_echo_rx_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "hold-time",
					      &sess->hold_time,
					      &sess->hold_time_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "ttl",
					     &sess->ttl,
					     &sess->ttl_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "detect-mult",
					     &sess->detect_mult,
					     &sess->detect_mult_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "ifindex",
					      &sess->ifindex,
					      &sess->ifindex_seen)) ||
		    (rc = bbdd_c_parse_kw_ifname(&argc, &argv, "ifname",
						 sess->ifname,
						 &sess->ifname_seen)) ||

		    (!seen_command &&
		     (rc = bbdd_c_parse_kw_flag(&argc, &argv, "bulk", &bulk)))) {
			if (rc > 0)
				continue;
			return rc;
		}

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	if (!seen_command) {
		fprintf(stderr, "No command given.\n");
		return -1;
	}

	if (bulk.seen && bulk.value) {
		if (command == bbdd_c_session_command_add) {
			fprintf(stderr, "`add' does not support bulk operations\n");
			return -1;
		}
		select.bulk = true;
	}

	if (bbdd_c_session_check_params(&select) < 0 ||
	    bbdd_c_session_check_params(&change) < 0)
		return -1;

	return bbdd_c_session_jrpc(command, &select, &change);
}

static int
bbdd_c_jrpc_dissect_params_session_list(struct json_object *obj,
					struct bbdd_c_session *sess,
					struct bbdd_c_session_state *state,
					char **error)
{
	enum {
		pol_data,
		pol_state,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_data] =  { .key = "data", .type = json_type_object,
				.required = true},
		[pol_state] =  { .key = "state", .type = json_type_object,
				 .required = true},
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	rc = bbdd_d_jrpc_dissect_params_session_one(values[pol_data], sess,
						    false, error);
	if (rc != 0)
		return rc;

	// xxx parse state
	*state = (struct bbdd_c_session_state){};
	return 0;
}

static int
bbdd_c_session_list_jrpc_dissect_sessions(struct json_object *sess_array,
					  struct bbdd_c_session **psessions,
					  struct bbdd_c_session_state **pstates,
					  size_t *pnum_sessions,
					  char **error)
{
	size_t sess_array_len = json_object_array_length(sess_array);
	struct bbdd_c_session *sessions;
	struct bbdd_c_session_state *states;

	if (bbdd_jrpc_validate_array(sess_array, json_type_object,
				     error) != 0)
		return -1;

	sessions = calloc(sess_array_len, sizeof(*sessions));
	if (sessions == NULL) {
		bbdd_jrpc_fmterr(error, "Couldn't allocate sessions: %m");
		return -1;
	}

	states = calloc(sess_array_len, sizeof(*states));
	if (states == NULL) {
		bbdd_jrpc_fmterr(error, "Couldn't allocate session states: %m");
		goto free_sessions;
	}

	for (size_t i = 0; i < sess_array_len; i++) {
		struct json_object *sess_obj =
			json_object_array_get_idx(sess_array, i);
		struct bbdd_c_session *session = &sessions[i];
		struct bbdd_c_session_state *state = &states[i];
		int err;

		err = bbdd_c_jrpc_dissect_params_session_list(sess_obj, session,
							      state, error);
		if (err != 0)
			goto free_sessions;
	}

	*psessions = sessions;
	*pstates = states;
	*pnum_sessions = sess_array_len;
	return 0;

free_sessions:
	free(sessions);
	return -1;
}

static int bbdd_c_session_list_jrpc_dissect(struct json_object *obj,
					    struct bbdd_c_session **sessions,
					    struct bbdd_c_session_state **states,
					    size_t *num_sessions,
					    char **error)
{
	/* Result for query with "get_tables" method is supposed to look
	 * like:
	 *
	 * { "sessions": [ SESS, ... ] }
	 *
	 * With each SESS a session object.
	 */
	enum {
		pol_sessions,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_sessions] = { .key = "sessions", .type = json_type_array,
				   .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = bbdd_jrpc_dissect(obj, policy, seen, values,
				ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	return bbdd_c_session_list_jrpc_dissect_sessions(values[pol_sessions],
							 sessions, states,
							 num_sessions, error);
}

static void bbdd_c_session_list_show_one(struct bbdd_c_session *sess,
					 struct bbdd_c_session_state *)
{
	bool seen = false;
	if (sess->lid_seen) {
		printf("lid %u ", sess->lid);
		seen = true;
	}
	if (sess->src_af) {
		printf("src %s ", sess->src);
		seen = true;
	}
	if (sess->dst_af) {
		printf("dst %s ", sess->dst);
		seen = true;
	}
	if (sess->min_tx_seen) {
		printf("min_tx %u ", sess->min_tx);
		seen = true;
	}
	if (sess->min_rx_seen) {
		printf("min_rx %u ", sess->min_rx);
		seen = true;
	}
	if (sess->min_echo_tx_seen) {
		printf("min_echo_tx %u ", sess->min_echo_tx_seen);
		seen = true;
	}
	if (sess->min_echo_rx_seen) {
		printf("min_echo_rx %u ", sess->min_echo_rx);
		seen = true;
	}
	if (sess->hold_time_seen) {
		printf("hold_time %u ", sess->hold_time);
		seen = true;
	}
	if (sess->ttl_seen) {
		printf("ttl %u ", sess->ttl);
		seen = true;
	}
	if (sess->detect_mult_seen) {
		printf("detect-mult %u ", sess->detect_mult);
		seen = true;
	}
	if (sess->ifindex_seen) {
		printf("ifindex %u ", sess->ifindex);
		seen = true;
	}
	if (sess->ifname_seen) {
		printf("ifname %s ", sess->ifname);
		seen = true;
	}

	// xxx show state

	if (!seen) {
		printf("(session without data)\n");
	} else {
		printf("\n");
	}
}

static int bbdd_c_session_list_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	struct bbdd_c_session *sessions;
	struct bbdd_c_session_state *states;
	size_t num_sessions;
	const int id = 1;
	char *error;
	int err;

	request = bbdd_jrpc_new_request(id, "session-list");
	if (request == NULL)
		return -1;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!bbdd_c_response_extract_result(response, id, json_type_object,
					    &result)) {
		err = -1;
		goto put_response;
	}

	if (bbdd_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	err = bbdd_c_session_list_jrpc_dissect(result, &sessions, &states,
					       &num_sessions, &error);
	if (err != 0) {
		fprintf(stderr, "Invalid session object: %s\n", error);
		free(error);
		goto put_result;
	}

	for (size_t i = 0; i < num_sessions; i++)
		bbdd_c_session_list_show_one(&sessions[i], &states[i]);
	if (num_sessions == 0 && bbdd_env.verbosity > 0)
		printf("(no sessions)\n");
	free(sessions);

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

static int bbdd_c_session_list(int argc, char **argv)
{
	int err;

	err = bbdd_c_cmd_noargs(argc, argv, bbdd_c_session_help);
	if (err != 0)
		return err;

	return bbdd_c_session_list_jrpc();
}

int bbdd_c_session(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		bbdd_c_session_help();
		return 0;
	} else if (strcmp(*argv, "list") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_session_list(argc, argv);
	}

	return bbdd_c_session_asd(argc, argv);
}
