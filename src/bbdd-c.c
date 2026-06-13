// SPDX-License-Identifier: GPL-2.0
#include "bbdd-c.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/linkhash.h>

#include "bbdd.h"
#include "bbdd-bfdd.h"
#include "bbdd-br.h"
#include "bbdd-d.h"
#include "bbdd-err.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-poll.h"
#include "bbdd-sock.h"
#include "bbdd-ssk.h"
#include "bbdd-util.h"

/* State information added by bbdd-bpf. */
struct bbdd_c_session_state_bpf {
	const char *bstate;
	struct bbdd_d_session_data_timing eff_timing;	bool eff_timing_seen;
	struct bbdd_d_session_data_timing poll_timing;	bool poll_timing_seen;
	bool qd_timing;					bool qd_timing_seen;
};

/* For carrying state information decoded from RPC. Most local session-specific
 * information is carried in bbdd_c_session. This contains the state & diag bits
 * for local session, and known remote session configuration. */
struct bbdd_c_session_state {
	struct bbdd_d_session_state_end local;		bool local_seen;
	struct bbdd_d_session_data remote;
	struct bbdd_c_session_state_bpf bpf;		bool bpf_seen;
};

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
		bbdd_err_print(&error, "Invalid error object");
		return;
	}

	if (bbdd_env.verbosity < 0)
		return;

	if (data != NULL)
		fprintf(stderr, "Error %" PRId64 ": %s (%s)\n", code, message,
			json_object_to_json_string(data));
	else
		fprintf(stderr, "Error %" PRId64 ": %s\n", code, message);
}

enum bbdd_c_result_rc {
	bbdd_c_result_rc_fail = -1,
	bbdd_c_result_rc_ok = 0,
	bbdd_c_result_rc_ok_error = 1,
};

static enum bbdd_c_result_rc
__bbdd_c_response_extract_result(struct json_object *j,
				 int expect_id,
				 enum json_type result_type,
				 struct json_object **ret_result,
				 char **error)
{
	struct json_object *result;
	struct json_object *id;
	bool is_error;
	int err;

	err = bbdd_jrpc_dissect_response(j, &id, &result, &is_error, error);
	if (err != 0) {
		bbdd_err_app(error, "Invalid response object");
		return bbdd_c_result_rc_fail;
	}

	if (!bbdd_c_validate_id(id, expect_id)) {
		bbdd_err_fmt(error, "Unknown response ID: %s",
			     json_object_to_json_string(id));
		return bbdd_c_result_rc_fail;
	}

	if (is_error) {
		bbdd_c_response_handle_error(result);
		return bbdd_c_result_rc_ok_error;
	}

	*ret_result = json_object_get(result);

	if (json_object_get_type(result) != result_type) {
		bbdd_err_fmt(error, "Unexpected result type: %s expected, got %s",
			     json_type_to_name(result_type),
			     json_type_to_name(json_object_get_type(result)));
		return bbdd_c_result_rc_fail;
	}

	return bbdd_c_result_rc_ok;
}

static bool bbdd_c_response_extract_result(struct json_object *j,
					   int expect_id,
					   enum json_type result_type,
					   struct json_object **ret_result)
{
	enum bbdd_c_result_rc rc;
	char *error;

	rc = __bbdd_c_response_extract_result(j, expect_id, result_type,
					      ret_result, &error);
	switch (rc) {
	case bbdd_c_result_rc_fail:
		bbdd_err_print(&error, NULL);
		return false;
	case bbdd_c_result_rc_ok_error:
		return false;
	case bbdd_c_result_rc_ok:
		return true;
	}

	assert(!"extract_result");
	__builtin_unreachable();
}

static void __bbdd_c_result_show_json(struct json_object *result)
{
	const char *dump;

	dump = json_object_to_json_string(result);
	fprintf(stdout, "%s\n", dump);
	fflush(stdout);
}

static bool bbdd_c_result_show_json(struct json_object *result)
{
	if (!bbdd_env.show_json)
		return false;

	__bbdd_c_result_show_json(result);
	return true;
}

struct bbdd_c {
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	struct bbdd_util_ssk_json_tkn *tkn;
	struct bbdd_ssk_c ctl;

	int (*cb)(struct json_object *result,
		  void *data, char **error);
	void *cb_data;
	enum json_type cb_expected_type;

	struct bbdd_ec ec; /* For error responses, even if the entire exchange
			    * was successful, we want to have non-0 exit code. */
};

static int __bbdd_c_ctl_recv_obj(struct json_object *response,
				 int (*cb)(struct json_object *result,
					   void *data, char **error),
				 void *cb_data, enum json_type cb_expected_type,
				 struct bbdd_ec *ec, char **error)
{
	struct json_object *result;
	enum bbdd_c_result_rc rrc;
	const int id = 1;
	int rc = 0;

	rrc = __bbdd_c_response_extract_result(response, id, cb_expected_type,
					       &result, error);
	switch (rrc) {
	case bbdd_c_result_rc_fail:
		return -1;
	case bbdd_c_result_rc_ok_error:
		*ec = bbdd_ec_failure;
		return 0;
	case bbdd_c_result_rc_ok:
		break;
	}

	if (bbdd_c_result_show_json(result))
		goto put_result;

	if (cb != NULL)
		rc = cb(result, cb_data, error);

put_result:
	json_object_put(result);
	return rc;
}

static int bbdd_c_ctl_recv_obj(struct bbdd_util_ssk_json_tkn *,
			       struct json_object *response, void *data,
			       char **error)
{
	struct bbdd_c *c = data;

	return __bbdd_c_ctl_recv_obj(response, c->cb, c->cb_data,
				     c->cb_expected_type, &c->ec, error);
}

static int bbdd_c_ssk_json_tkn_rx_cb(struct bbdd_ssk_peer *peer,
				     const char *buf, size_t len,
				     void *data, char **error)
{
	struct bbdd_c *c = data;

	return bbdd_util_ssk_json_tkn_rx_cb(peer, buf, len, c->tkn, error);
}

static void bbdd_c_ssk_json_tkn_done_cb(struct bbdd_ssk_peer *, void *data)
{
	struct bbdd_c *c = data;

	bbdd_poll_request_quit(c->pctx);
}

static struct bbdd_ec
bbdd_c_interact(struct json_object **request,
		int (*cb)(struct json_object *response, void *data,
			  char **error),
		void *data, enum json_type cb_expected_type,
		const struct bbdd_mon_topics *topics)
{
	struct bbdd_c c = {
		.cb = cb,
		.cb_data = data,
		.cb_expected_type = cb_expected_type,
		.ec = bbdd_ec_success,
	};
	struct bbdd_sockaddr bsa;
	struct bbdd_ssk_cbs cbs;
	const char *request_str;
	int rc = -ENOMEM;
	char *error;

	c.mon = bbdd_mon_create(bbdd_env.mon_eager, &error);
	if (c.mon == NULL)
		goto err;

	rc = bbdd_mon_subscribe_cb(c.mon, bbdd_c_monitor_dispatch, NULL,
				   *topics, &error);
	if (rc != 0)
		goto mon_fini;

	c.pctx = bbdd_poll_init(c.mon, &error);
	if (c.pctx == NULL)
		goto mon_fini;

	rc = bbdd_ctl_sockaddr(bbdd_env.sockdir, &bsa, &error);
	if (rc != 0)
		goto poll_fini;

	c.tkn = bbdd_util_ssk_json_tkn_create(bbdd_c_ctl_recv_obj, &c, &error);
	if (c.tkn == NULL) {
		rc = -1;
		goto poll_fini;
	}

	cbs = (struct bbdd_ssk_cbs) {
		.rx_cb = bbdd_c_ssk_json_tkn_rx_cb,
		.done_cb = bbdd_c_ssk_json_tkn_done_cb,
		.data = &c,
	};

	rc = bbdd_ssk_open_c(&c.ctl, c.pctx, &bsa, cbs, &error);
	if (rc != 0)
		goto tkn_destroy;

	rc = bbdd_poll_set_signals(c.pctx, &error);
	if (rc != 0)
		goto ssk_close_ctl;

	request_str = json_object_to_json_string(*request);
	if (request_str == NULL) {
		bbdd_err_fmt(&error, "Failed to serialize JSON object");
		goto unset_signals;
	}

	rc = bbdd_ssk_c_nq(&c.ctl, request_str, strlen(request_str), &error);
	if (rc != 0)
		goto unset_signals;
	if (bbdd_env.cli_imm_done) {
		bbdd_mon_send_debug(c.mon, "cli-imm-done: Marking peer as done");
		bbdd_ssk_peer_mark_done(c.ctl.base.peers);
	}

	json_object_put(*request);
	*request = NULL;
	request_str = NULL;

	rc = bbdd_poll_loop(c.pctx, &error);

unset_signals:
	bbdd_poll_unset_signals(c.pctx);
ssk_close_ctl:
	bbdd_ssk_close_c(&c.ctl);
tkn_destroy:
	bbdd_util_ssk_json_tkn_destroy(c.tkn);
poll_fini:
	bbdd_poll_fini(c.pctx);
mon_fini:
	bbdd_mon_destroy(c.mon);
err:
	if (rc != 0) {
		bbdd_err_print(&error, "Communication error");
		return bbdd_ec_failure;
	}
	return c.ec;
}

static struct json_object *bbdd_c_send_request_on(struct json_object *request,
						  struct bbdd_sock *cli,
						  struct bbdd_sock *peer)
{
	struct json_object *response_obj = NULL;
	char *response;
	char *error;
	int err;

	err = bbdd_util_jrpc_send(peer, request, &error);
	if (err < 0) {
		bbdd_err_print(&error, "Failed to send the RPC message");
		return NULL;
	}

	err = bbdd_sock_recv(cli, peer, &response, &error);
	if (err < 0) {
		bbdd_err_print(&error, "Failed to receive an RPC response");
		return NULL;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		bbdd_err_fmt(&error, "Failed to parse RPC response as JSON.");
		bbdd_err_print(&error, NULL);
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
	char *error;
	int err;

	err = bbdd_sock_open_c(&cli, &peer, bbdd_env.sockdir, &error);
	if (err < 0) {
		bbdd_err_print(&error, "Failed to open a socket");
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

static void bbdd_c_echo_help(void)
{
	fprintf(stderr,
		"Usage: bbdd echo\n"
		"\n"
	);
}

static int bbdd_c_echo_jrpc_res(struct json_object *result,
				void *, char **error)
{
	enum {
		pol_ts,
		pol_reply_ts,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_ts]       = { .key = "ts",       .type = json_type_int,
				   .required = true },
		[pol_reply_ts] = { .key = "reply_ts", .type = json_type_int,
				   .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	uint64_t reply_ts_us;
	uint64_t delay_us;
	uint64_t ts_us;
	int rc;

	rc = bbdd_jrpc_dissect(result, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0) {
		bbdd_err_app(error, "echo result");
		return rc;
	}

	if (bbdd_env.verbosity <= 0)
		return rc;

	ts_us = json_object_get_uint64(values[pol_ts]);
	reply_ts_us = json_object_get_uint64(values[pol_reply_ts]);
	delay_us = reply_ts_us - ts_us;

	fprintf(stdout, "echo reply: latency %" PRIu64 " us\n", delay_us);
	return 0;
}

static struct bbdd_ec bbdd_c_echo_jrpc(const char *method,
				       const struct bbdd_mon_topics *topics)
{
	struct bbdd_ec ec = bbdd_ec_failure;
	struct json_object *request;
	struct json_object *params;
	const int id = 1;
	uint64_t ts_us;

	request = bbdd_jrpc_new_request(id, method);
	if (request == NULL)
		goto out;

	params = json_object_new_object();
	if (params == NULL)
		goto put_request;

	ts_us = bbdd_util_now();
	if (bbdd_jrpc_append_uint64(params, "ts", ts_us))
		goto put_params;

	if (bbdd_jrpc_append_obj(request, "params", &params))
		goto put_params;

	ec = bbdd_c_interact(&request, bbdd_c_echo_jrpc_res, NULL,
			     json_type_object, topics);

put_params:
	json_object_put(params);
put_request:
	json_object_put(request);
out:
	return ec;
}

struct bbdd_ec bbdd_c_echo(int argc, char **argv,
			   const struct bbdd_mon_topics *topics)
{
	int rc;

	rc = bbdd_c_cmd_noargs(argc, argv, bbdd_c_echo_help);
	if (rc != 0)
		return bbdd_ec_failure;

	return bbdd_c_echo_jrpc("echo", topics);
}

static void bbdd_c_stop_help(void)
{
	fprintf(stderr,
		"Usage: bbdd stop\n"
		"\n"
	);
}

static int bbdd_c_stop_jrpc_res(struct json_object *, void *, char **)
{
	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bbdd will stop\n");
	return 0;
}

static struct bbdd_ec bbdd_c_stop_jrpc(const struct bbdd_mon_topics *topics)
{
	struct json_object *request;
	const int id = 1;

	request = bbdd_jrpc_new_request(id, "stop");
	if (request == NULL)
		return bbdd_ec_failure;

	return bbdd_c_interact(&request, bbdd_c_stop_jrpc_res, NULL,
			       json_type_null, topics);
}

struct bbdd_ec bbdd_c_stop(int argc, char **argv,
			   const struct bbdd_mon_topics *topics)
{
	int rc;

	rc = bbdd_c_cmd_noargs(argc, argv, bbdd_c_stop_help);
	if (rc != 0)
		return bbdd_ec_failure;

	return bbdd_c_stop_jrpc(topics);
}

static void bbdd_c_global_stats_help(void)
{
	fprintf(stderr,
		"Usage: bbdd global diag stats\n"
		"       diag		-- request diagnostic stats instead of operational ones\n"
	);
}

static void bbdd_c_print_stats_obj(struct json_object *obj)
{
	json_object_object_foreach(obj, key, val) {
		if (json_object_get_type(val) != json_type_int)
			continue;
		printf("\t%s: %" PRIu64 "\n", key, json_object_get_uint64(val));
	}
}

static int bbdd_c_global_stats_get_jrpc_res(struct json_object *result,
					    void *, char **)
{
	printf("global:\n");
	bbdd_c_print_stats_obj(result);
	return 0;
}

static struct bbdd_ec
bbdd_c_global_stats_get_jrpc(const struct bbdd_mon_topics *topics)
{
	struct json_object *request;
	const int id = 1;

	request = bbdd_jrpc_new_request(id, "global-stats-diag");
	if (request == NULL)
		return bbdd_ec_failure;

	return bbdd_c_interact(&request, bbdd_c_global_stats_get_jrpc_res, NULL,
			       json_type_object, topics);
}

static int bbdd_c_session_act_jrpc_result(struct json_object *,
					  const char *method)

{
	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "`%s' was handled by the daemon\n", method);

	return 0;
}

static int
__bbdd_c_jrpc_dissect_session_data(struct json_object *obj,
				   struct bbdd_d_session_data *data,
				   bool state_only, char **error)
{
	enum {
		/* State-only policy. */
		pol_state,
		pol_diag,
		polsize_state_only,

		/* Rest of the complete policy. */
		pol_discr = polsize_state_only,
		pol_detect_mult,
		pol_min_tx_us,
		pol_min_rx_us,
		pol_cpi,
		polsize_full,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_state] = { .key = "state", .type = json_type_string,
				.required = true },
		[pol_diag] = { .key = "diag", .type = json_type_string,
			       .required = true },
		[pol_discr] = { .key = "discr",
				.type = json_type_int, .required = true },
		[pol_detect_mult] = { .key = "detect_mult",
				      .type = json_type_int, .required = true },
		[pol_min_tx_us] = { .key = "min_tx_us",
				    .type = json_type_int, .required = true },
		[pol_min_rx_us] = { .key = "min_rx_us",
				    .type = json_type_int, .required = true },
		[pol_cpi] = { .key = "cpi", .type = json_type_boolean },
	};
	const size_t polsize = state_only ? polsize_state_only : polsize_full;
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	const char *state_str;
	const char *diag_str;
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, polsize, error);
	if (rc != 0)
		return rc;

	state_str = json_object_get_string(values[pol_state]);
	rc = bbdd_d_bfd_state_from_str(state_str, &data->state.state);
	if (rc < 0) {
		bbdd_err_fmt(error, "Invalid session state `%s'", state_str);
		return rc;
	}

	diag_str = json_object_get_string(values[pol_diag]);
	rc = bbdd_d_bfd_diag_from_str(diag_str, &data->state.diag);
	if (rc < 0) {
		bbdd_err_fmt(error, "Invalid session diag `%s'", diag_str);
		return rc;
	}

#define __DISSECT(PNAME, DNAME, CB) do {				\
		if (seen[pol_ ## PNAME]) {				\
			if (CB(values[pol_ ## PNAME], &data->DNAME,	\
			       error) < 0)				\
				return -1;				\
		}							\
	} while (0)
#define DISSECT_U32(PNAME, DNAME) __DISSECT(PNAME, DNAME, bbdd_jrpc_get_uint32)

	DISSECT_U32(discr, discr);
	__DISSECT(detect_mult, timing.detect_mult, bbdd_jrpc_get_uint8);
	DISSECT_U32(min_tx_us, timing.min_tx_us);
	DISSECT_U32(min_rx_us, timing.min_rx_us);

	data->flags.cpi = json_object_get_boolean(values[pol_cpi]);

#undef DISSECT_U32
#undef __DISSECT

	return 0;
}

static int
bbdd_c_jrpc_dissect_session_state_remote(struct json_object *obj,
					 struct bbdd_d_session_data *remote,
					 char **error)
{
	return __bbdd_c_jrpc_dissect_session_data(obj, remote, false, error);
}

static int
bbdd_c_jrpc_dissect_session_state_local(struct json_object *obj,
					struct bbdd_d_session_state_end *local,
					char **error)
{
	struct bbdd_d_session_data data;
	int rc;

	rc = __bbdd_c_jrpc_dissect_session_data(obj, &data, true, error);
	if (rc != 0)
		return rc;

	*local = data.state;
	return 0;
}

static int
bbdd_c_jrpc_dissect_timing(struct json_object *obj,
			   struct bbdd_d_session_data_timing *timing,
			   char **error)
{
	enum {
		pol_detect_mult,
		pol_min_tx_us,
		pol_min_rx_us,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_detect_mult] = { .key = "detect_mult", .type = json_type_int,
				      .required = true },
		[pol_min_tx_us]   = { .key = "min_tx_us",   .type = json_type_int,
				      .required = true },
		[pol_min_rx_us]   = { .key = "min_rx_us",   .type = json_type_int,
				      .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	if (bbdd_jrpc_get_uint8(values[pol_detect_mult], &timing->detect_mult, error) < 0 ||
	    bbdd_jrpc_get_uint32(values[pol_min_tx_us], &timing->min_tx_us, error) < 0 ||
	    bbdd_jrpc_get_uint32(values[pol_min_rx_us], &timing->min_rx_us, error) < 0)
		return -1;
	return 0;
}

static int
bbdd_c_jrpc_dissect_session_state_bpf(struct json_object *obj,
				      struct bbdd_c_session_state_bpf *bstate,
				      char **error)
{
	enum {
		pol_bstate,
		pol_eff_timing,
		pol_poll_timing,
		pol_qd_timing,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_bstate]     = { .key = "bstate",     .type = json_type_string },
		[pol_eff_timing] = { .key = "eff_timing", .type = json_type_object },
		[pol_poll_timing] = { .key = "poll_timing", .type = json_type_object },
		[pol_qd_timing]  = { .key = "qd_timing",  .type = json_type_boolean },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	if (seen[pol_bstate])
		bstate->bstate = json_object_get_string(values[pol_bstate]);
	if (seen[pol_eff_timing]) {
		bstate->eff_timing_seen = true;
		rc = bbdd_c_jrpc_dissect_timing(values[pol_eff_timing],
						&bstate->eff_timing, error);
		if (rc != 0)
			return rc;
	}
	if (seen[pol_poll_timing]) {
		bstate->poll_timing_seen = true;
		rc = bbdd_c_jrpc_dissect_timing(values[pol_poll_timing],
						&bstate->poll_timing, error);
		if (rc != 0)
			return rc;
	}
	if (seen[pol_qd_timing]) {
		bstate->qd_timing_seen = true;
		bstate->qd_timing = json_object_get_boolean(values[pol_qd_timing]);
	}

	return 0;
}

static int
bbdd_c_jrpc_dissect_session_state(struct json_object *obj,
				  struct bbdd_c_session_state *state,
				  char **error)
{
	enum {
		pol_local,
		pol_remote,
		pol_bpf,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_local]      = { .key = "local",      .type = json_type_object },
		[pol_remote]     = { .key = "remote",     .type = json_type_object,
				     .required = true },
		[pol_bpf]        = { .key = "bpf",        .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	if (seen[pol_local]) {
		rc = bbdd_c_jrpc_dissect_session_state_local(values[pol_local],
							     &state->local, error);
		if (rc != 0)
			return rc;

		state->local_seen = true;
	} else {
		state->local_seen = false;
	}

	rc = bbdd_c_jrpc_dissect_session_state_remote(values[pol_remote],
						      &state->remote, error);
	if (rc != 0)
		return rc;

	if (seen[pol_bpf]) {
		rc = bbdd_c_jrpc_dissect_session_state_bpf(values[pol_bpf],
							   &state->bpf, error);
		if (rc != 0)
			return rc;

		state->bpf_seen = true;
	} else {
		state->bpf_seen = false;
	}

	return 0;
}

static int bbdd_c_jrpc_dissect_session_elem(struct json_object *obj,
					    struct bbdd_c_session *csess,
					    struct bbdd_c_session_state *state,
					    char **error)
{
	enum {
		pol_data,
		pol_state,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_data] = { .key = "data", .type = json_type_object,
			       .required = true},
		[pol_state] = { .key = "state", .type = json_type_object,
				.required = true},
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	rc = bbdd_d_jrpc_dissect_session_one(values[pol_data], csess, error);
	if (rc != 0)
		return rc;

	rc = bbdd_c_jrpc_dissect_session_state(values[pol_state], state, error);
	if (rc != 0)
		return rc;

	return 0;
}

static int
bbdd_c_session_show_jrpc_dissect_sessions(struct json_object *sess_array,
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
		bbdd_err_fmt(error, "Couldn't allocate sessions: %m");
		return -1;
	}

	states = calloc(sess_array_len, sizeof(*states));
	if (states == NULL) {
		bbdd_err_fmt(error, "Couldn't allocate session states: %m");
		goto free_sessions;
	}

	for (size_t i = 0; i < sess_array_len; i++) {
		struct json_object *sess_obj =
			json_object_array_get_idx(sess_array, i);
		struct bbdd_c_session *session = &sessions[i];
		struct bbdd_c_session_state *state = &states[i];
		int err;

		err = bbdd_c_jrpc_dissect_session_elem(sess_obj, session,
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

static int
bbdd_c_response_extract_sessions(struct json_object *obj,
				 struct json_object **ret_sessions_arr,
				 char **error)
{
	/* This extracts result in the following form:
	 *
	 * { "sessions": [ OBJ, ... ] }
	 */
	enum {
		pol_sessions,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_sessions] = { .key = "sessions", .type = json_type_array,
				   .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	struct json_object *sessions_arr;
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = bbdd_jrpc_dissect(obj, policy, seen, values,
				ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	sessions_arr = values[pol_sessions];

	err = bbdd_jrpc_validate_array(sessions_arr, json_type_object, error);
	if (err != 0)
		return err;

	*ret_sessions_arr = sessions_arr;
	return 0;
}

static int bbdd_c_session_show_jrpc_dissect(struct json_object *obj,
					    struct bbdd_c_session **sessions,
					    struct bbdd_c_session_state **states,
					    size_t *num_sessions,
					    char **error)
{
	struct json_object *sessions_arr;
	int err;

	err = bbdd_c_response_extract_sessions(obj, &sessions_arr, error);
	if (err != 0)
		return err;

	return bbdd_c_session_show_jrpc_dissect_sessions(sessions_arr,
							 sessions, states,
							 num_sessions, error);
}

static void
bbdd_c_session_show_state_end(const struct bbdd_d_session_state_end *end)
{
	printf("state %s diag %s ",
	       bbdd_d_bfd_state_to_str(end->state),
	       bbdd_d_bfd_diag_to_str(end->diag));
}

/* Only uint32_t should ever be valid, but we use the function for dumping of
 * monitoring events as well, and it makes no sense to validate those, so allow
 * dumping of uint64_t. */
static void bbdd_c_show_time_us(const char *label, uint64_t us)
{
	if (bbdd_env.numeric) {
		printf("%s %" PRIu64 " ", label, us);
		return;
	}
	if (us % 1000000 == 0)
		printf("%s %" PRIu64 "s ", label, us / 1000000);
	else if (us % 1000 == 0)
		printf("%s %" PRIu64 "ms ", label, us / 1000);
	else
		printf("%s %" PRIu64 "us ", label, us);
}

static void
bbdd_c_session_show_state_bpf(const struct bbdd_c_session_state_bpf *bstate)
{
	if (bstate->bstate != NULL)
		printf("state %s ", bstate->bstate);
	if (bstate->eff_timing_seen) {
		printf("eff-timing detect-mult %u ",
			bstate->eff_timing.detect_mult);
		bbdd_c_show_time_us("min-tx",
				    bstate->eff_timing.min_tx_us);
		bbdd_c_show_time_us("min-rx",
				    bstate->eff_timing.min_rx_us);
	}
	if (bstate->poll_timing_seen) {
		printf("poll-timing detect-mult %u ", bstate->poll_timing.detect_mult);
		bbdd_c_show_time_us("min-tx", bstate->poll_timing.min_tx_us);
		bbdd_c_show_time_us("min-rx", bstate->poll_timing.min_rx_us);
	}
	if (bstate->qd_timing_seen)
		printf("qd-timing %s ", bstate->qd_timing ? "yes" : "no");
}

static void bbdd_c_show_flag(const char *name, bool flag, bool *seen)
{
	if (flag || bbdd_env.verbosity > 0) {
		printf("%s%s ", flag ? "" : "no ", name);
		if (seen != NULL)
			*seen = true;
	}
}

static void
bbdd_c_session_show_data(const struct bbdd_d_session_data *data)
{
	printf("discr %u ", data->discr);
	printf("detect-mult %u ", data->timing.detect_mult);
	bbdd_c_show_time_us("min-tx", data->timing.min_tx_us);
	bbdd_c_show_time_us("min-rx", data->timing.min_rx_us);
	bbdd_c_show_flag("cpi", data->flags.cpi, NULL);
	bbdd_c_session_show_state_end(&data->state);
}

static bool bbdd_c_session_show_netif(const struct bbdd_c_session_netif *netif,
				      const char *kw)
{
	bool seen = false;

	/* Prefer name to index, but show both in verbose mode. */

	if (netif->name_seen) {
		printf("%s %s ", kw, netif->name);
		seen = true;
	}

	if ((!netif->name_seen || bbdd_env.verbosity > 0) &&
	    netif->ifindex_seen) {
		printf("%s-index %u ", kw, netif->ifindex);
		seen = true;
	}

	/* Show the negative form in verbose mode. */
	if (netif->unset && bbdd_env.verbosity > 0) {
		printf("no %s ", kw);
		seen = true;
	}

	return seen;
}

static void bbdd_c_session_show_one(struct bbdd_c_session *csess,
				    struct bbdd_c_session_state *state)
{
	bool seen = false;
	bool seen_vrf;

	if (csess->discr_seen) {
		printf("discr %u ", csess->discr);
		seen = true;
	}
	if (csess->remote_discr_seen) {
		printf("remote-discr %u ", csess->remote_discr);
		seen = true;
	}
	if (csess->src.unset) {
		if (bbdd_env.verbosity > 0) {
			printf("no src ");
			seen = true;
		}
	} else if (csess->src.af) {
		printf("src %s ", csess->src.str);
		seen = true;
	}

	if (csess->dst.af) {
		printf("dst %s ", csess->dst.str);
		seen = true;
	}
	if (csess->min_tx_us_seen) {
		bbdd_c_show_time_us("min-tx", csess->min_tx_us);
		seen = true;
	}
	if (csess->min_rx_us_seen) {
		bbdd_c_show_time_us("min-rx", csess->min_rx_us);
		seen = true;
	}
	if (csess->hold_time_us_seen) {
		bbdd_c_show_time_us("hold-time", csess->hold_time_us);
		seen = true;
	}
	if (csess->ttl_seen) {
		printf("ttl %u ", csess->ttl);
		seen = true;
	}
	if (csess->detect_mult_seen) {
		printf("detect-mult %u ", csess->detect_mult);
		seen = true;
	}

	if (bbdd_c_session_show_netif(&csess->netif, "netif"))
		seen = true;

	/* Prefer VRF name to table ID, but show both in verbose mode. */
	seen_vrf = bbdd_c_session_show_netif(&csess->vrf.netif, "vrf");
	if ((!seen_vrf || bbdd_env.verbosity > 0) &&
	    csess->vrf.table_seen) {
		printf("vrf-table %d ", csess->vrf.table);
		seen_vrf = true;
	}
	if (seen_vrf)
		seen = true;

#define SHOW_FLAG(NAME, name, ...)					\
		if (csess->flags.name.seen)				\
			bbdd_c_show_flag(#name, csess->flags.name.value, \
					 &seen);

	BBDD_SESS_FLAGS(SHOW_FLAG);

#undef SHOW_FLAG

	if (!seen)
		printf("(session without data)");

	if (state == NULL)
		return;

	if (state->local_seen) {
		printf("| local ");
		bbdd_c_session_show_state_end(&state->local);
	}

	printf("| remote ");
	bbdd_c_session_show_data(&state->remote);

	if (bbdd_env.verbosity > 0 && state->bpf_seen) {
		printf("| bpf ");
		bbdd_c_session_show_state_bpf(&state->bpf);
	}
}

static int bbdd_c_session_show_jrpc_result(struct json_object *result,
					   const char *)
{
	struct bbdd_c_session *sessions;
	struct bbdd_c_session_state *states;
	size_t num_sessions;
	char *error;
	int err;

	err = bbdd_c_session_show_jrpc_dissect(result, &sessions, &states,
					       &num_sessions, &error);
	if (err != 0) {
		fprintf(stderr, "Invalid session object: %s\n", error);
		free(error);
		return 0;
	}

	for (size_t i = 0; i < num_sessions; i++) {
		bbdd_c_session_show_one(&sessions[i], &states[i]);
		printf("\n");
	}
	if (num_sessions == 0 && bbdd_env.verbosity > 0)
		printf("(no sessions)\n");
	free(sessions);
	free(states);
	return 0;
}

static int bbdd_c_session_stats_dissect_one(struct json_object *obj,
					    char **error)
{
	enum {
		pol_discr,
		pol_stats,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_discr] = { .key = "discr", .type = json_type_int,
				.required = true },
		[pol_stats] = { .key = "stats", .type = json_type_object,
				.required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	printf("discr %" PRIu32 ":\n",
	       (uint32_t)json_object_get_uint64(values[pol_discr]));
	bbdd_c_print_stats_obj(values[pol_stats]);
	return 0;
}

static int bbdd_c_session_stats_dissect_result(struct json_object *obj,
					       char **error)
{
	struct json_object *sessions_arr;
	int err;

	err = bbdd_c_response_extract_sessions(obj, &sessions_arr, error);
	if (err != 0)
		return err;

	for (size_t i = 0; i < json_object_array_length(sessions_arr); i++) {
		struct json_object *session_obj =
			json_object_array_get_idx(sessions_arr, i);

		err = bbdd_c_session_stats_dissect_one(session_obj, error);
		if (err != 0)
			return err;
	}

	return 0;
}

static int bbdd_c_session_stats_jrpc_result(struct json_object *result,
					    const char *)
{
	char *error = NULL;
	int err = 0;

	err = bbdd_c_session_stats_dissect_result(result, &error);
	if (err != 0) {
		fprintf(stderr, "%s\n", error);
		free(error);
	}

	return err;
}

static struct bbdd_c_session_command {
	const char *const name;
	const bool allow_bulk;
	const bool allow_diag;
	const bool allow_query;
	const bool allow_change;
	const char *const rpc;
	const char *const rpc_diag;
	enum json_type expected_result_type;
	int (*show)(struct json_object *, const char *method);
} const bbdd_c_session_commands[] = {
	{
		.name = "add",
		.allow_change = true,
		.rpc = "session-add",
		.show = bbdd_c_session_act_jrpc_result,
		.expected_result_type = json_type_null,
	},
	{
		.name = "set",
		.allow_bulk = true,
		.allow_query = true,
		.allow_change = true,
		.rpc = "session-set",
		.show = bbdd_c_session_act_jrpc_result,
		.expected_result_type = json_type_null,
	},
	{
		.name = "del",
		.allow_bulk = true,
		.allow_query = true,
		.rpc = "session-del",
		.show = bbdd_c_session_act_jrpc_result,
		.expected_result_type = json_type_null,
	},
	{
		.name = "show",
		.allow_query = true,
		.rpc = "session-show",
		.show = bbdd_c_session_show_jrpc_result,
		.expected_result_type = json_type_object,
	},
	{
		.name = "stats",
		.allow_diag = true,
		.allow_query = true,
		.rpc = "session-stats",
		.rpc_diag = "session-stats-diag",
		.show = bbdd_c_session_stats_jrpc_result,
		.expected_result_type = json_type_object,
	},
};

enum {
	bbdd_c_session_ncommands = ARRAY_SIZE(bbdd_c_session_commands),
};

static void bbdd_c_session_help(void)
{
	fprintf(stderr,
		"Usage:	bbdd session add [ SET-PARAMS ]\n"
		"	bbdd session [ QUERY-PARAMS ] [bulk] set [ SET-PARAMS ]\n"
		"	bbdd session [ QUERY-PARAMS ] [bulk] del\n"
		"	bbdd session [ QUERY-PARAMS ] show\n"
		"	bbdd session [ QUERY-PARAMS ] [diag] stats\n"
		"\n"
		"	bulk		-- request is allowed to impact >1 session\n"
		"	diag		-- request diagnostic stats instead of operational ones\n"
		"\n"
		"where	QUERY-PARAMS := PARAMS	-- parameters for session select\n"
		"	SET-PARAMS := PARAMS	-- adjusted / new session parameters\n"
		"	PARAMS ::= PARAM [ PARAMS ]\n"
		"	PARAM ::= { KEY VALUE | no UNSET-KEY | [ no ] FLAG }\n"
		"	KEY ::= { discr | remote-discr | src | dst | min-tx | min-rx |\n"
		"	          hold-time | ttl | detect-mult | netif | netif-index |\n"
		"	          vrf | vrf-index | vrf-table }\n"
		"	UNSET-KEY ::= { remote-discr | src | netif | vrf }\n"
		"	FLAG ::= { multihop | cpi | passive | shutdown }\n"
		"	no FLAG		-- set the flag to negative value\n"
		"	no NETIF-KEY	-- unset a given key\n"
		"\n"
		"Parameter KEY and VALUE details:\n"
		"	discr U32 	-- session discriminator\n"
		"	remote-discr U32 -- default remote discriminator\n"
		"	src ADDR	-- source address\n"
		"	dst ADDR	-- destination address\n"
		"	min-tx TIME	-- minimum tx interval (e.g. 100us, 10ms, 1s)\n"
		"	min-rx TIME	-- minimum rx interval (e.g. 100us, 10ms, 1s)\n"
		"	hold-time U32	-- session start wait time in miliseconds\n"
		"	ttl U8		-- minimum packet TTL\n"
		"	detect-mult U8	-- detection multiplier\n"
		"	netif STR	-- interface name\n"
		"	netif-index U32	-- interface index\n"
		"	vrf STR		-- VRF interface name\n"
		"	vrf-index U32	-- VRF interface index\n"
		"	table U32	-- routing table ID\n"
		"\n"
		"where	U8 := 8-bit numerical value (0..255)\n"
		"	U32 := 32-bit numerical value (0..4Gi)\n"
		"	STR := a string value\n"
		"	ADDR := an IPv4 or IPv6 network address\n"
		"	TIME := <U32>[<UNIT>], amount of time with a unit attached (e.g. 100ms)\n"
		"	UNIT := {us | ms | s} for microseconds (default), miliseconds, seconds\n"
		"\n"
		"FLAG details:\n"
		"	multihop	-- multi-hop session\n"
		"	cpi		-- control-plane independent\n"
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
		     const char *kw, struct bbdd_flag *flag)
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

struct bbdd_ec bbdd_c_global(int argc, char **argv,
			     const struct bbdd_mon_topics *topics)
{
	struct bbdd_flag diag = {};
	bool seen_stats = false;
	int rc;

	while (argc > 0) {
		if (strcmp(*argv, "stats") == 0) {
			if (seen_stats) {
				fprintf(stderr, "Duplicate `stats'.\n");
				return bbdd_ec_failure;
			}
			NEXT_ARG_FWD();
			seen_stats = true;
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			bbdd_c_global_stats_help();
			return bbdd_ec_success;
		}

		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "diag", &diag))) {
			if (rc > 0)
				continue;
			if (rc != 0)
				return bbdd_ec_failure;
			return bbdd_ec_success;
		}

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return bbdd_ec_failure;
	}

	if (!seen_stats) {
		fprintf(stderr, "No command given.\n");
		return bbdd_ec_failure;
	}

	if (!diag.seen || !diag.value) {
		fprintf(stderr, "Only `diag' stats are currently supported.\n");
		return bbdd_ec_failure;
	}

	return bbdd_c_global_stats_get_jrpc(topics);
}

static int bbdd_c_parse_u8(const char *str, void *ret, const char *what)
{
	uint8_t *u8_ret = ret;
	char *error;
	int rc;

	rc = bbdd_sock_parse_u8(str, u8_ret, what, &error);
	if (rc != 0)
		bbdd_err_print(&error, NULL);
	return rc;
}

static int bbdd_c_parse_u32(const char *str, void *ret, const char *what)
{
	uint32_t *u32_ret = ret;
	char *error;
	int rc;

	rc = bbdd_sock_parse_u32(str, u32_ret, what, &error);
	if (rc != 0)
		bbdd_err_print(&error, NULL);
	return rc;
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

/* Like bbdd_c_parse_kw_u32, but also accepts `no KW' as a synonym for the
 * value 0. */
static int bbdd_c_parse_kw_u32_no(int *up_argc, char ***up_argv, const char *kw,
				  uint32_t *ret, int *ret_seen)
{
	struct bbdd_flag flag = {
		.seen = *ret_seen,
		.value = false,
	};
	int rc;

	rc = bbdd_c_parse_kw_u32(up_argc, up_argv, kw, ret, ret_seen);
	if (rc != 0)
		return rc;

	rc = bbdd_c_parse_kw_flag(up_argc, up_argv, kw, &flag);
	if (rc <= 0)
		return rc;

	assert(flag.value == false);
	*ret = 0;
	*ret_seen = 1;
	return 1;
}

static int bbdd_c_parse_time_us(const char *str, void *ret, const char *what)
{
	char *error;
	int rc;

	rc = bbdd_util_parse_time_us(str, ret, &error);
	if (rc != 0)
		bbdd_err_print(&error, "Can't parse %s `%s'", what, str);
	return rc;
}

static int bbdd_c_parse_kw_time_us(int *up_argc, char ***up_argv, const char *kw,
				   uint32_t *ret, int *ret_seen)
{
	return bbdd_c_parse_kw(up_argc, up_argv, kw, ret, ret_seen,
			       bbdd_c_parse_time_us);
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

static int
bbdd_c_session_parse_netif_check_apply(struct bbdd_c_session_netif *ret_netif,
				       struct bbdd_c_session_netif *new_netif,
				       const char *kw, const char *flag_kw)
{
	if (ret_netif->unset) {
		fprintf(stderr, "Duplicate keyword `%s', `no %s' already given.\n",
			kw, flag_kw);
		return -1;
	}

	*ret_netif = *new_netif;
	return 1;
}

static int
bbdd_c_session_parse_netif_ifindex(int *up_argc, char ***up_argv,
				   const char *flag_kw, const char *ix_kw,
				   struct bbdd_c_session_netif *ret_netif)
{
	struct bbdd_c_session_netif netif = *ret_netif;
	int rc;

	rc = bbdd_c_parse_kw_u32(up_argc, up_argv, ix_kw,
				 &netif.ifindex, &netif.ifindex_seen);
	if (rc <= 0)
		return rc;

	return bbdd_c_session_parse_netif_check_apply(ret_netif, &netif,
						      ix_kw, flag_kw);
}

static int
bbdd_c_session_parse_netif_kw(int *up_argc, char ***up_argv, const char *kw,
			      struct bbdd_c_session_netif *ret_netif)
{
	struct bbdd_c_session_netif netif = *ret_netif;
	int rc;

	rc = bbdd_c_parse_kw_ifname(up_argc, up_argv, kw,
				    netif.name, &netif.name_seen);
	if (rc <= 0)
		return rc;

	return bbdd_c_session_parse_netif_check_apply(ret_netif, &netif,
						      kw, kw);
}

static int
bbdd_c_session_parse_netif_flag(int *up_argc, char ***up_argv,
				const char *kw, const char *ix_kw,
				struct bbdd_c_session_netif *ret_netif)
{
	struct bbdd_flag flag = {
		.seen = ret_netif->unset,
		.value = false,
	};
	int rc;

	rc = bbdd_c_parse_kw_flag(up_argc, up_argv, kw, &flag);
	if (rc <= 0)
		return rc;

	if (ret_netif->name_seen) {
		fprintf(stderr, "Duplicate keyword `no %s', `%s' already given.\n",
			kw, kw);
		return -1;
	}
	if (ret_netif->ifindex_seen) {
		fprintf(stderr, "Duplicate keyword `no %s', `%s' already given.\n",
			kw, ix_kw);
		return -1;
	}

	ret_netif->unset = true;
	return 1;
}

static int bbdd_c_session_parse_netif(int *up_argc, char ***up_argv,
				      const char *kw,
				      struct bbdd_c_session_netif *ret_netif)
{
#define INDEX "-index"
	char ix_kw[strlen(kw) + sizeof(INDEX)];
	strcpy(stpcpy(ix_kw, kw), INDEX);
#undef INDEX

	/* Parse this as either `<kw>-index X', or `<kw> X', or when both fail,
	 * as `no <kw>'. */
	return bbdd_c_session_parse_netif_ifindex(up_argc, up_argv, kw, ix_kw,
						  ret_netif) ?:
	       bbdd_c_session_parse_netif_kw(up_argc, up_argv, kw, ret_netif) ?:
	       bbdd_c_session_parse_netif_flag(up_argc, up_argv, kw, ix_kw,
					       ret_netif);
}

static int
bbdd_c_session_parse_addr_kw(int *up_argc, char ***up_argv, const char *kw,
			     struct bbdd_c_session_addr *ret_addr)
{
	struct bbdd_c_session_addr addr = *ret_addr;
	int rc;

	rc = bbdd_c_parse_kw_addr(up_argc, up_argv, kw, addr.str, &addr.af);
	if (rc <= 0)
		return rc;

	if (ret_addr->unset) {
		fprintf(stderr, "Duplicate keyword `%s', `no %s' already given.\n",
			kw, kw);
		return -1;
	}

	*ret_addr = addr;
	return 1;
}

static int
bbdd_c_session_parse_addr_flag(int *up_argc, char ***up_argv, const char *kw,
			       struct bbdd_c_session_addr *ret_addr)
{
	struct bbdd_flag flag = {
		.seen = ret_addr->unset,
		.value = false,
	};
	int rc;

	rc = bbdd_c_parse_kw_flag(up_argc, up_argv, kw, &flag);
	if (rc <= 0)
		return rc;

	if (ret_addr->af != 0) {
		fprintf(stderr, "Duplicate keyword `no %s', `%s' already given.\n",
			kw, kw);
		return -1;
	}

	ret_addr->unset = true;
	return 1;
}

static int bbdd_c_session_parse_addr(int *up_argc, char ***up_argv,
				     const char *kw,
				     struct bbdd_c_session_addr *addr)
{
	return bbdd_c_session_parse_addr_kw(up_argc, up_argv, kw, addr) ?:
	       bbdd_c_session_parse_addr_flag(up_argc, up_argv, kw, addr);
}

static int bbdd_c_enomem(void)
{
	fprintf(stderr, "Failed to form RPC request: %m");
	return -ENOMEM;
}

static int bbdd_c_jrpc_append_netif(struct json_object *params_obj,
				    const char *base,
				    const struct bbdd_c_session_netif *netif)
{
#define INDEX "_index"
#define NAME "_name"
	char ix_key[strlen(base) + sizeof(INDEX)];
	char nm_key[strlen(base) + sizeof(NAME)];
	strcpy(stpcpy(ix_key, base), INDEX);
	strcpy(stpcpy(nm_key, base), NAME);
#undef INDEX

	if ((netif->unset &&
	     json_object_object_add(params_obj, nm_key, NULL)) ||
	    (netif->name_seen &&
	     bbdd_jrpc_append_str(params_obj, nm_key, netif->name)) ||
	    (netif->ifindex_seen &&
	     bbdd_jrpc_append_int(params_obj, ix_key, netif->ifindex)))
		return -1;
	return 0;
}

static int bbdd_c_jrpc_append_addr(struct json_object *params_obj,
				   const char *kw,
				   const struct bbdd_c_session_addr *addr)
{
	struct json_object *obj;

	if (addr->unset)
		return json_object_object_add(params_obj, kw, NULL);
	if (addr->af == 0)
		return 0;

	obj = bbdd_util_jrpc_addr_obj(addr->str, addr->af);
	if (obj == NULL)
		return -1;

	if (json_object_object_add(params_obj, kw, obj))
		goto obj_put;

	return 0;

obj_put:
	json_object_put(obj);
	return -1;
}

struct json_object *bbdd_c_jrpc_session_obj(const struct bbdd_c_session *csess)
{
	struct json_object *params_obj;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto err;

	for (int i = 0; i < bbdd_sess_nflags; i++) {
		const struct bbdd_flag *flag = &csess->flags.flags[i];
		const char *flag_name = bbdd_sess_flag_name(i);

		if (!flag->seen)
			continue;

		if (bbdd_jrpc_append_bool(params_obj, flag_name, flag->value))
			goto put_params_obj;
	}

	if ((csess->discr_seen &&
	     bbdd_jrpc_append_int(params_obj, "discr", csess->discr)) ||
	    (csess->remote_discr_seen &&
	     bbdd_jrpc_append_int(params_obj, "remote_discr",
				  csess->remote_discr)) ||
	    (csess->min_tx_us_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_tx_us", csess->min_tx_us)) ||
	    (csess->min_rx_us_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_rx_us", csess->min_rx_us)) ||
	    (csess->hold_time_us_seen &&
	     bbdd_jrpc_append_int(params_obj, "hold_time_us",
				  csess->hold_time_us)) ||
	    (csess->ttl_seen &&
	     bbdd_jrpc_append_int(params_obj, "ttl", csess->ttl)) ||
	    (csess->detect_mult_seen &&
	     bbdd_jrpc_append_int(params_obj, "detect_mult",
				  csess->detect_mult)) ||
	    bbdd_c_jrpc_append_addr(params_obj, "src", &csess->src) ||
	    bbdd_c_jrpc_append_addr(params_obj, "dst", &csess->dst) ||
	    bbdd_c_jrpc_append_netif(params_obj, "netif", &csess->netif) ||
	    bbdd_c_jrpc_append_netif(params_obj, "vrf", &csess->vrf.netif) ||
	    (csess->vrf.table_seen &&
	     bbdd_jrpc_append_int(params_obj, "vrf_table", csess->vrf.table)))
		goto put_params_obj;

	return params_obj;

put_params_obj:
	json_object_put(params_obj);
err:
	bbdd_c_enomem();
	return NULL;
}

static int bbdd_c_session_jrpc_res(struct json_object *result,
				   void *data, char **)
{
	const struct bbdd_c_session_command *command = data;

	return command->show(result, command->rpc);
}

static struct bbdd_ec
bbdd_c_session_jrpc(const struct bbdd_c_session_command *command,
		    const struct bbdd_c_session *select,
		    const struct bbdd_c_session *change,
		    struct bbdd_flag bulk,
		    struct bbdd_flag diag,
		    const struct bbdd_mon_topics *topics)
{
	struct bbdd_ec ec = bbdd_ec_failure;
	struct json_object *select_obj = NULL;
	struct json_object *change_obj = NULL;
	struct json_object *params_obj;
	struct json_object *request;
	const char *method;
	const int id = 1;

	if (command->allow_query) {
		select_obj = bbdd_c_jrpc_session_obj(select);
		if (select_obj == NULL)
			return ec;
	}

	if (command->allow_change) {
		change_obj = bbdd_c_jrpc_session_obj(change);
		if (change_obj == NULL)
			goto put_select;
	}

	if (diag.seen && diag.value)
		method = command->rpc_diag;
	else
		method = command->rpc;

	assert(method != NULL);

	request = bbdd_jrpc_new_request(id, method);
	if (request == NULL)
		goto put_select_change;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto put_request;

	if ((select_obj != NULL &&
	     bbdd_jrpc_append_obj(params_obj, "select", &select_obj)) ||
	    (change_obj != NULL &&
	     bbdd_jrpc_append_obj(params_obj, "change", &change_obj)) ||
	    (bulk.seen && bulk.value &&
	     bbdd_jrpc_append_bool(params_obj, "bulk", bulk.value)) ||
	    bbdd_jrpc_append_obj(request, "params", &params_obj))
		goto put_params_obj;

	ec = bbdd_c_interact(&request,
			     bbdd_c_session_jrpc_res, (void *) command,
			     command->expected_result_type, topics);

put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
put_select_change:
	json_object_put(change_obj);
put_select:
	json_object_put(select_obj);
	return ec;
}

static void
bbdd_c_session_check_params_netif(const struct bbdd_c_session_netif *netif)
{
	/* Just make sure we haven't screwed up the constraints on netifs. */
	if (netif->unset) {
		assert(!netif->name_seen);
		assert(!netif->ifindex_seen);
	}
	if (netif->name_seen)
		assert(!netif->unset);
	if (netif->ifindex_seen)
		assert(!netif->unset);
}

static int bbdd_c_session_check_params(struct bbdd_c_session *csess)
{
	bbdd_c_session_check_params_netif(&csess->netif);
	bbdd_c_session_check_params_netif(&csess->vrf.netif);
	return 0;
}

struct bbdd_ec bbdd_c_session(int argc, char **argv,
			      const struct bbdd_mon_topics *topics)
{
	struct bbdd_c_session select = {};
	struct bbdd_c_session change = {};
	struct bbdd_c_session *csess = &select;
	bool seen_arg = false;
	struct bbdd_flag bulk = {};
	struct bbdd_flag diag = {};
	const struct bbdd_c_session_command *command = NULL;
	int rc;

	while (argc > 0) {
		bool arg_was_command = false;
		for (int i = 0; i < bbdd_c_session_ncommands; i++) {
			const struct bbdd_c_session_command *command2 =
						    &bbdd_c_session_commands[i];
			if (strcmp(*argv, command2->name) != 0)
				continue;
			if (command != NULL) {
				fprintf(stderr, "`%s' seen when a command `%s' was already given\n",
					*argv, command->name);
				return bbdd_ec_failure;
			}

			command = command2;
			arg_was_command = true;

			if (!command->allow_query && seen_arg) {
				fprintf(stderr, "`%s' used with session query parameters\n",
					command->name);
				return bbdd_ec_failure;
			}

			if (command->allow_change)
				csess = &change;
			else
				csess = NULL;

			NEXT_ARG_FWD();
			break;
		}

		if (arg_was_command)
			continue;

		if (strcmp(*argv, "help") == 0) {
			bbdd_c_session_help();
			return bbdd_ec_success;
		}

		if (csess == NULL) {
			fprintf(stderr, "`%s' used with session change parameters\n",
				command->name);
			return bbdd_ec_failure;
		}

		seen_arg = true;

		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "multihop",
					       &csess->flags.multihop)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "cpi",
					       &csess->flags.cpi)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "passive",
					       &csess->flags.passive)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "shutdown",
					       &csess->flags.shutdown)) ||

		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "discr",
					      &csess->discr,
					      &csess->discr_seen)) ||
		    (rc = bbdd_c_parse_kw_u32_no(&argc, &argv, "remote-discr",
						 &csess->remote_discr,
						 &csess->remote_discr_seen)) ||
		    (rc = bbdd_c_parse_kw_time_us(&argc, &argv, "min-tx",
						  &csess->min_tx_us,
						  &csess->min_tx_us_seen)) ||
		    (rc = bbdd_c_parse_kw_time_us(&argc, &argv, "min-rx",
						  &csess->min_rx_us,
						  &csess->min_rx_us_seen)) ||
		    (rc = bbdd_c_parse_kw_time_us(&argc, &argv, "hold-time",
						  &csess->hold_time_us,
						  &csess->hold_time_us_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "ttl",
					     &csess->ttl,
					     &csess->ttl_seen)) ||
		    (rc = bbdd_c_parse_kw_u8(&argc, &argv, "detect-mult",
					     &csess->detect_mult,
					     &csess->detect_mult_seen)) ||
		    (rc = bbdd_c_session_parse_addr(&argc, &argv,
						    "src", &csess->src)) ||
		    (rc = bbdd_c_session_parse_addr(&argc, &argv,
						    "dst", &csess->dst)) ||
		    (rc = bbdd_c_session_parse_netif(&argc, &argv,
						     "netif", &csess->netif)) ||
		    (rc = bbdd_c_session_parse_netif(&argc, &argv,
						     "vrf", &csess->vrf.netif)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "vrf-table",
					      &csess->vrf.table,
					      &csess->vrf.table_seen)) ||

		    (command == NULL &&
		     (rc = bbdd_c_parse_kw_flag(&argc, &argv, "bulk", &bulk))) ||
		    (command == NULL &&
		     (rc = bbdd_c_parse_kw_flag(&argc, &argv, "diag", &diag)))) {
			if (rc > 0)
				continue;
			if (rc != 0)
				return bbdd_ec_failure;
			return bbdd_ec_success;
		}

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return bbdd_ec_failure;
	}

	if (command == NULL) {
		fprintf(stderr, "No command given.\n");
		return bbdd_ec_failure;
	}
	if (bulk.seen && !command->allow_bulk) {
		fprintf(stderr, "`bulk' not supported for `%s'.\n",
			command->name);
		return bbdd_ec_failure;
	}
	if (diag.seen && !command->allow_diag) {
		fprintf(stderr, "`diag' not supported for `%s'.\n",
			command->name);
		return bbdd_ec_failure;
	}

	if (bbdd_c_session_check_params(&select) < 0 ||
	    bbdd_c_session_check_params(&change) < 0)
		return bbdd_ec_failure;

	return bbdd_c_session_jrpc(command, &select, &change, bulk, diag,
				   topics);
}

static struct bbdd_ec
bbdd_c_bfdd_connect_jrpc(const char *proto, const char *addr, const char *port,
			 const struct bbdd_mon_topics *topics)
{
	struct bbdd_ec ec = bbdd_ec_failure;
	struct json_object *params_obj;
	struct json_object *request;
	const int id = 1;

	request = bbdd_jrpc_new_request(id, "bfdd-connect");
	if (request == NULL)
		return bbdd_ec_failure;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto put_request;

	if (bbdd_jrpc_append_str(params_obj, "proto", proto) ||
	    bbdd_jrpc_append_str(params_obj, "addr", addr) ||
	    (port != NULL &&
	     bbdd_jrpc_append_str(params_obj, "port", port)) ||
	    bbdd_jrpc_append_obj(request, "params", &params_obj))
		goto put_params_obj;

	ec = bbdd_c_interact(&request, NULL, NULL, json_type_null, topics);

put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return ec;
}

static void bbdd_c_bfdd_connect_help(void)
{
	fprintf(stderr, "%s",
		"Usage: bbdd bfdd connect [TYPE:ADDRESS[:PORT]]\n"
		"TYPE ::= {ipv4 | ipv6 | unix}\n"
		"Default connect address is `" BBDD_BFDD_DEFAULT_ADDR "'.\n"
		"\n"
	);
}

static struct bbdd_ec bbdd_c_bfdd_connect(int argc, char **argv,
					  const struct bbdd_mon_topics *topics)
{
	struct bbdd_ec ec = bbdd_ec_failure;
	const char *proto;
	const char *addr;
	const char *port;
	const char *arg;
	char *copy;
	char *error;
	int rc;

	if (!argc) {
		arg = BBDD_BFDD_DEFAULT_ADDR;
	} else if (strcmp(*argv, "help") == 0) {
		bbdd_c_bfdd_connect_help();
		return bbdd_ec_success;
	} else {
		arg = *argv;
	}

	copy = strdup(arg);
	rc = bbdd_sock_split_addr_proto(copy, &proto, &addr, &port, &error);
	if (rc < 0) {
		bbdd_err_print(&error, "bfdd connect");
		goto out;
	}

	ec = bbdd_c_bfdd_connect_jrpc(proto, addr, port, topics);

out:
	free(copy);
	return ec;
}

static struct bbdd_ec bbdd_c_bfdd_disconnect(int argc, char **argv)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	if (argc > 0) {
		fprintf(stderr, "Usage: bbdd bfdd disconnect\n\n");
		if (strcmp(*argv, "help") == 0)
			return bbdd_ec_success;
		else
			return bbdd_ec_failure;
	}

	request = bbdd_jrpc_new_request(id, "bfdd-disconnect");
	if (request == NULL)
		return bbdd_ec_failure;

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

	bbdd_c_result_show_json(result);
	err = 0;

	json_object_put(result);
put_request:
	json_object_put(request);
put_response:
	json_object_put(response);
	return err != 0 ? bbdd_ec_failure : bbdd_ec_success;
}

static struct bbdd_ec bbdd_c_bfdd_connected(int argc, char **argv)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	bool connected;
	const int id = 1;
	int err;

	if (argc > 0) {
		fprintf(stderr, "Usage: bbdd bfdd connected\n\n");
		if (strcmp(*argv, "help") == 0)
			return bbdd_ec_success;
		else
			return bbdd_ec_failure;
	}

	request = bbdd_jrpc_new_request(id, "bfdd-connected");
	if (request == NULL)
		return bbdd_ec_failure;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!bbdd_c_response_extract_result(response, id, json_type_boolean,
					    &result)) {
		err = -1;
		goto put_response;
	}

	connected = json_object_get_boolean(result);
	err = connected ? 0 : 1;

	if (bbdd_c_result_show_json(result))
		goto out;
	if (bbdd_env.verbosity > 0)
		printf("connected: %s\n", connected ? "yes" : "no");

out:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err != 0 ? bbdd_ec_failure : bbdd_ec_success;
}

static struct bbdd_ec bbdd_c_bfdd_echo(int argc, char **argv,
				       const struct bbdd_mon_topics *topics)
{
	int rc;

	rc = bbdd_c_cmd_noargs(argc, argv, NULL);
	if (rc != 0) {
		fprintf(stderr, "Usage: bbdd bfdd echo\n\n");
		return bbdd_ec_failure;
	}

	return bbdd_c_echo_jrpc("bfdd-echo", topics);
}

static void bbdd_c_bfdd_help(void)
{
	fprintf(stderr,
		"Usage: bbdd bfdd { bridge | connect | connected | disconnect | echo | help }\n"
		"\n"
	);
}

struct bbdd_ec bbdd_c_bfdd(int argc, char **argv,
			   const struct bbdd_mon_topics *topics)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		bbdd_c_bfdd_help();
		return bbdd_ec_success;
	} else if (strcmp(*argv, "bridge") == 0) {
		NEXT_ARG_FWD();
		if (!argc || strcmp(*argv, "help") == 0) {
			fprintf(stderr,
				"Usage: bbdd bfdd bridge { start | help }\n\n");
			return bbdd_ec_success;
		} else if (strcmp(*argv, "start") == 0) {
			NEXT_ARG_FWD();
			return bbdd_br_start(argc, argv, topics);
		}
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return bbdd_ec_failure;
	} else if (strcmp(*argv, "connect") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_connect(argc, argv, topics);
	} else if (strcmp(*argv, "connected") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_connected(argc, argv);
	} else if (strcmp(*argv, "disconnect") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_disconnect(argc, argv);
	} else if (strcmp(*argv, "echo") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_echo(argc, argv, topics);
	}

	fprintf(stderr, "What is \"%s\"?\n", *argv);
	return bbdd_ec_failure;
}

static void bbdd_c_monitor_help(void)
{
#define SHOW_TOPIC(NAME, DEFAULT) " | " #NAME

	fprintf(stderr,
		"Usage: bbdd monitor [ TOPICS ]\n"
		"\n"
		"where  TOPICS := TOPIC [ TOPICS ]\n"
		"       TOPIC  := { all" BBDD_MON_TOPICS(SHOW_TOPIC) " }\n"
		"\n"
		"Subscribe to daemon monitoring topics and print received notifications.\n"
		"When no TOPICS are given, all topics are subscribed.\n"
	);

#undef SHOW_TOPIC
}

static int bbdd_c_monitor_dissect_addr_str(struct json_object *obj,
					   const char **ret_str, char **error)
{
	enum {
		pol_addr,
		pol_family,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_addr]   = { .key = "addr",   .type = json_type_string,
				 .required = true },
		[pol_family] = { .key = "family", .type = json_type_string },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	*ret_str = json_object_get_string(values[pol_addr]);
	return 0;
}

struct bbdd_c_monitor_packet {
	struct json_object *version;
	struct json_object *bits;
	struct json_object *state;
	struct json_object *diag;
	struct json_object *detect_mult;
	struct json_object *my_disc;
	struct json_object *your_disc;
	struct json_object *desired_tx;
	struct json_object *required_rx;
};

static int bbdd_c_monitor_dissect_packet(struct json_object *bfd_obj,
					 struct bbdd_c_monitor_packet *packet,
					 char **error)
{
	enum {
		pol_version,
		pol_bits,
		pol_state,
		pol_diag,
		pol_detect_mult,
		pol_my_disc,
		pol_your_disc,
		pol_desired_tx,
		pol_required_rx,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_version]     = { .key = "version",
				      .type = json_type_int },
		[pol_bits]        = { .key = "bits",
				      .type = json_type_array },
		[pol_state]       = { .key = "state",
				      .type = json_type_string },
		[pol_diag]        = { .key = "diag",
				      .type = json_type_string },
		[pol_detect_mult] = { .key = "detect_mult",
				      .type = json_type_int },
		[pol_my_disc]     = { .key = "my-disc",
				      .type = json_type_int },
		[pol_your_disc]   = { .key = "your-disc",
				      .type = json_type_int },
		[pol_desired_tx]  = { .key = "desired-tx",
				      .type = json_type_int },
		[pol_required_rx] = { .key = "required-rx",
				      .type = json_type_int },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(bfd_obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	if (seen[pol_bits]) {
		rc = bbdd_jrpc_validate_array(values[pol_bits],
					      json_type_string, error);
		if (rc != 0)
			return rc;
	}

#define FIELD(F) .F = seen[pol_ ## F] ? values[pol_ ## F] : NULL

	*packet = (struct bbdd_c_monitor_packet) {
		FIELD(version),
		FIELD(bits),
		FIELD(state),
		FIELD(diag),
		FIELD(detect_mult),
		FIELD(my_disc),
		FIELD(your_disc),
		FIELD(desired_tx),
		FIELD(required_rx),
	};

	return 0;

#undef FIELD
}

enum bbdd_c_monitor_print_rc {
	BBDD_C_MONITOR_PRINT_ERROR,
	BBDD_C_MONITOR_PRINT_NOTHING,
	BBDD_C_MONITOR_PRINT_OK,
	BBDD_C_MONITOR_PRINT_UNHANDLED,
};

static void
bbdd_c_monitor_print_packet(const struct bbdd_c_monitor_packet *packet)
{
	printf("bfd [ ");
	if (packet->version != NULL)
		printf("version %" PRIu64 " ",
		       json_object_get_uint64(packet->version));
	if (packet->bits != NULL) {
		printf("bits [ ");

		for (size_t i = 0, len = json_object_array_length(packet->bits);
		     i < len; i++) {
			struct json_object *elm;

			elm = json_object_array_get_idx(packet->bits, i);
			printf("%s ", json_object_get_string(elm));
		}
		printf("] ");
	}
	if (packet->state != NULL)
		printf("state %s ", json_object_get_string(packet->state));
	if (packet->diag != NULL)
		printf("diag %s ", json_object_get_string(packet->diag));
	if (packet->detect_mult != NULL)
		printf("detect-mult %" PRIu64 " ",
		       json_object_get_uint64(packet->detect_mult));
	if (packet->my_disc != NULL)
		printf("my-disc %" PRIu64 " ",
		       json_object_get_uint64(packet->my_disc));
	if (packet->your_disc != NULL)
		printf("your-disc %" PRIu64 " ",
		       json_object_get_uint64(packet->your_disc));
	if (packet->desired_tx != NULL) {
		uint64_t us = json_object_get_uint64(packet->desired_tx);
		bbdd_c_show_time_us("desired-tx", us);
	}
	if (packet->required_rx != NULL) {
		uint64_t us = json_object_get_uint64(packet->required_rx);
		bbdd_c_show_time_us("required-rx", us);
	}
	printf("] ");
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_message(struct json_object *params, char **error)
{
	enum {
		pol_msg,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_msg]  = { .key = "msg",  .type = json_type_string },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	assert(rc == 0);

	if (seen[pol_msg]) {
		printf("%s", json_object_get_string(values[pol_msg]));
		rc = 1;
	}

	return rc == 1 ? BBDD_C_MONITOR_PRINT_OK
		       : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_ringbuf_rx_discr_0(struct json_object *params,
					 char **error)
{
	enum {
		pol_ifindex,
		pol_wire_len,
		pol_ttl,
		pol_multihop,
		pol_src,
		pol_dst,
		pol_bfd,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_ifindex]  = { .key = "ifindex",  .type = json_type_int },
		[pol_wire_len] = { .key = "wire-len", .type = json_type_int },
		[pol_ttl]      = { .key = "ttl",      .type = json_type_int },
		[pol_multihop] = { .key = "multihop", .type = json_type_boolean },
		[pol_src]      = { .key = "src",      .type = json_type_object },
		[pol_dst]      = { .key = "dst",      .type = json_type_object },
		[pol_bfd]      = { .key = "bfd",      .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct bbdd_c_monitor_packet packet;
	const char *src_str = NULL;
	const char *dst_str = NULL;
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_src]) {
		rc = bbdd_c_monitor_dissect_addr_str(values[pol_src], &src_str,
						     error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
	}

	if (seen[pol_dst]) {
		rc = bbdd_c_monitor_dissect_addr_str(values[pol_dst], &dst_str,
						     error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
	}

	if (seen[pol_bfd]) {
		rc = bbdd_c_monitor_dissect_packet(values[pol_bfd], &packet,
						   error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
	}

	assert(rc == 0);

	if (seen[pol_ifindex]) {
		printf("ifindex %" PRIu64 " ",
		       json_object_get_uint64(values[pol_ifindex]));
		rc = 1;
	}
	if (seen[pol_wire_len]) {
		printf("wire-len %" PRIu64 " ",
		       json_object_get_uint64(values[pol_wire_len]));
		rc = 1;
	}
	if (seen[pol_src]) {
		printf("src %s ", src_str);
		rc = 1;
	}
	if (seen[pol_dst]) {
		printf("dst %s ", dst_str);
		rc = 1;
	}
	if (seen[pol_ttl]) {
		printf("ttl %" PRIu64 " ",
		       json_object_get_uint64(values[pol_ttl]));
		rc = 1;
	}
	if (seen[pol_multihop] &&
	    json_object_get_boolean(values[pol_multihop])) {
		printf("multihop ");
		rc = 1;
	}
	if (seen[pol_bfd]) {
		bbdd_c_monitor_print_packet(&packet);
		rc = 1;
	}

	return rc == 1 ? BBDD_C_MONITOR_PRINT_OK
		       : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_ringbuf_rx_unx_pkt(struct json_object *params,
					 char **error)
{
	enum {
		pol_wire_len,
		pol_ttl,
		pol_bfd,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_wire_len] = { .key = "wire-len", .type = json_type_int },
		[pol_ttl]     = { .key = "ttl",     .type = json_type_int },
		[pol_bfd]     = { .key = "bfd",     .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct bbdd_c_monitor_packet packet;
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_bfd]) {
		rc = bbdd_c_monitor_dissect_packet(values[pol_bfd], &packet,
						   error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
	}

	assert(rc == 0);

	if (seen[pol_wire_len]) {
		printf("wire-len %" PRIu64 " ",
		       json_object_get_uint64(values[pol_wire_len]));
		rc = 1;
	}
	if (seen[pol_ttl]) {
		printf("ttl %" PRIu64 " ",
		       json_object_get_uint64(values[pol_ttl]));
		rc = 1;
	}
	if (seen[pol_bfd]) {
		bbdd_c_monitor_print_packet(&packet);
		rc = 1;
	}

	return rc == 1 ? BBDD_C_MONITOR_PRINT_OK
		       : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_ringbuf_rx_timeout(struct json_object *params,
					 char **error)
{
	enum {
		pol_discr,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_discr] = { .key = "discr", .type = json_type_int },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	assert(rc == 0);

	if (seen[pol_discr]) {
		printf("discr %" PRIu64 " ",
		       json_object_get_uint64(values[pol_discr]));
		rc = 1;
	}

	return rc == 1 ? BBDD_C_MONITOR_PRINT_OK
		       : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_ringbuf_tx_no_neigh(struct json_object *params,
					  char **error)
{
	enum {
		pol_ifindex,
		pol_addr,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_ifindex] = { .key = "ifindex", .type = json_type_int },
		[pol_addr]    = { .key = "addr",    .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	const char *addr_str;
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_addr]) {
		rc = bbdd_c_monitor_dissect_addr_str(values[pol_addr], &addr_str,
						     error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
	}

	assert(rc == 0);

	if (seen[pol_ifindex]) {
		printf("ifindex %" PRIu64 " ",
		       json_object_get_uint64(values[pol_ifindex]));
		rc = 1;
	}
	if (seen[pol_addr]) {
		printf("addr %s ", addr_str);
		rc = 1;
	}

	return rc == 1 ? BBDD_C_MONITOR_PRINT_OK
		       : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_session_change(struct json_object *params, char **error)
{
	enum {
		pol_discr,
		pol_session,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_discr]   = { .key = "discr",   .type = json_type_int },
		[pol_session] = { .key = "session", .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct bbdd_c_session_state state = {};
	struct bbdd_c_session csess = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_session]) {
		rc = bbdd_c_jrpc_dissect_session_elem(values[pol_session],
						      &csess, &state, error);
		if (rc != 0) {
			bbdd_err_print(error, NULL);
			goto try_discr;
		}
		bbdd_c_session_show_one(&csess, &state);
		return BBDD_C_MONITOR_PRINT_OK;
	}

try_discr:
	if (seen[pol_discr]) {
		printf("discr %" PRIu64 " ",
		       json_object_get_uint64(values[pol_discr]));
		return BBDD_C_MONITOR_PRINT_OK;
	}

	return BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_bfdd_sess_add(struct json_object *params, char **error)
{
	enum {
		pol_session,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_session] = { .key = "session", .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct bbdd_c_session csess = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_session]) {
		rc = bbdd_d_jrpc_dissect_session_one(values[pol_session],
						     &csess, error);
		if (rc != 0)
			return BBDD_C_MONITOR_PRINT_ERROR;
		bbdd_c_session_show_one(&csess, NULL);
		return BBDD_C_MONITOR_PRINT_OK;
	}

	return BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_bfdd_lid_msg(struct json_object *params, char **error)
{
	enum {
		pol_lid,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_lid] = { .key = "lid", .type = json_type_int },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_lid]) {
		printf("lid %" PRIu64 " ",
		       json_object_get_uint64(values[pol_lid]));
		return BBDD_C_MONITOR_PRINT_OK;
	}

	return BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_bfdd_echo(struct json_object *params, char **error)
{
	enum {
		pol_dp_time,
		pol_bfdd_time,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_dp_time]   = { .key = "dp-time",   .type = json_type_int },
		[pol_bfdd_time] = { .key = "bfdd-time", .type = json_type_int },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_dp_time]) {
		printf("dp-time %" PRIu64 " ",
		       json_object_get_uint64(values[pol_dp_time]));
		rc = 1;
	}
	if (seen[pol_bfdd_time]) {
		printf("bfdd-time %" PRIu64 " ",
		       json_object_get_uint64(values[pol_bfdd_time]));
		rc = 1;
	}

	return rc ? BBDD_C_MONITOR_PRINT_OK : BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_bfdd_empty(struct json_object *params, char **error)
{
	if (params != NULL) {
		bbdd_err_fmt(error, "parameters expected to be nil");
		return BBDD_C_MONITOR_PRINT_ERROR;
	}

	return BBDD_C_MONITOR_PRINT_NOTHING;
}

static enum bbdd_c_monitor_print_rc
bbdd_c_monitor_handle_bfdd_unknown(struct json_object *params, char **error)
{
	enum {
		pol_type,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_type] = { .key = "type", .type = json_type_int },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(params, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return BBDD_C_MONITOR_PRINT_ERROR;

	if (seen[pol_type]) {
		printf("type %" PRIu64 " ",
		       json_object_get_uint64(values[pol_type]));
		return BBDD_C_MONITOR_PRINT_OK;
	}

	return BBDD_C_MONITOR_PRINT_NOTHING;
}

static void bbdd_c_monitor_print_ts_fmt(time_t sec, long ms, bool local)
{
	struct tm tm;

	localtime_r(&sec, &tm);
	printf("[%s%04d-%02d-%02dT%02d:%02d:%02d.%03ld] ",
	       local ? "!" : "",
	       tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	       tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void bbdd_c_monitor_print_ts(struct json_object *ts_obj)
{
	uint64_t ts_ms = json_object_get_uint64(ts_obj);

	bbdd_c_monitor_print_ts_fmt((time_t)(ts_ms / 1000), ts_ms % 1000, false);
}

static void bbdd_c_monitor_print_timestamp(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	bbdd_c_monitor_print_ts_fmt(ts.tv_sec, ts.tv_nsec / 1000000, true);
}

static void bbdd_c_monitor_handle_notif(const char *method,
					struct json_object *outer_params)
{
	enum bbdd_c_monitor_print_rc rc = BBDD_C_MONITOR_PRINT_UNHANDLED;
	enum {
		pol_ts,
		pol_params,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_ts]     = { .key = "ts",     .type = json_type_int },
		[pol_params] = { .key = "params", .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct json_object *ts_obj;
	struct json_object *params;
	char *error;

	if (bbdd_c_result_show_json(outer_params))
		return;

	bbdd_jrpc_dissect(outer_params, policy, seen, values,
			  ARRAY_SIZE(policy), NULL);
	ts_obj = values[pol_ts];
	params = values[pol_params];

	if (bbdd_env.timestamp) {
		if (ts_obj != NULL)
			bbdd_c_monitor_print_ts(ts_obj);
		else
			bbdd_c_monitor_print_timestamp();
	}

	printf("%-20s: ", method);

	if (strcmp(method, "debug") == 0)
		rc = bbdd_c_monitor_handle_message(params, &error);
	else if (strcmp(method, "error") == 0)
		rc = bbdd_c_monitor_handle_message(params, &error);
	else if (strcmp(method, "ringbuf:rx-discr-0") == 0)
		rc = bbdd_c_monitor_handle_ringbuf_rx_discr_0(params, &error);
	else if (strcmp(method, "ringbuf:rx-unx-pkt") == 0)
		rc = bbdd_c_monitor_handle_ringbuf_rx_unx_pkt(params, &error);
	else if (strcmp(method, "ringbuf:rx-timeout") == 0)
		rc = bbdd_c_monitor_handle_ringbuf_rx_timeout(params, &error);
	else if (strcmp(method, "ringbuf:tx-no-neigh") == 0)
		rc = bbdd_c_monitor_handle_ringbuf_tx_no_neigh(params, &error);
	else if (strcmp(method, "session:change") == 0)
		rc = bbdd_c_monitor_handle_session_change(params, &error);
	else if (strcmp(method, "bfddi:sess-add") == 0 ||
		 strcmp(method, "bfddo:sess-add") == 0)
		rc = bbdd_c_monitor_handle_bfdd_sess_add(params, &error);
	else if (strcmp(method, "bfddi:state-change") == 0 ||
		 strcmp(method, "bfddo:state-change") == 0)
		rc = bbdd_c_monitor_handle_session_change(params, &error);
	else if (strcmp(method, "bfddi:sess-del") == 0 ||
		 strcmp(method, "bfddo:sess-del") == 0 ||
		 strcmp(method, "bfddi:sess-cnt-req") == 0 ||
		 strcmp(method, "bfddo:sess-cnt-req") == 0)
		rc = bbdd_c_monitor_handle_bfdd_lid_msg(params, &error);
	else if (strcmp(method, "bfddi:echo-req") == 0 ||
		 strcmp(method, "bfddo:echo-req") == 0 ||
		 strcmp(method, "bfddi:echo-rep") == 0 ||
		 strcmp(method, "bfddo:echo-rep") == 0)
		rc = bbdd_c_monitor_handle_bfdd_echo(params, &error);
	else if (strcmp(method, "bfddi:sess-cnt-rep") == 0 ||
		 strcmp(method, "bfddo:sess-cnt-rep") == 0)
		rc = bbdd_c_monitor_handle_bfdd_empty(params, &error);
	else if (strcmp(method, "bfddi:unknown") == 0 ||
		 strcmp(method, "bfddo:unknown") == 0)
		rc = bbdd_c_monitor_handle_bfdd_unknown(params, &error);

	switch (rc) {
	case BBDD_C_MONITOR_PRINT_ERROR:
		bbdd_err_print(&error, "Failed to dissect monitor event `%s'",
			       method);
		/* Fall through. */
	case BBDD_C_MONITOR_PRINT_UNHANDLED:
		__bbdd_c_result_show_json(params);
		break;

	case BBDD_C_MONITOR_PRINT_NOTHING:
		printf("(no data)");
		/* Fall through. */
	case BBDD_C_MONITOR_PRINT_OK:
		printf("\n");
		break;
	}
}

struct bbdd_c_monitor_ctx {
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	struct bbdd_util_ssk_json_tkn *tkn;
	struct bbdd_ssk_c ctl;
	struct bbdd_ec ec;
};

static int bbdd_c_monitor_recv_cb(struct bbdd_util_ssk_json_tkn *,
				  struct json_object *notif_obj, void *,
				  char **)
{
	struct json_object *params;
	const char *method;
	char *error;
	int err;

	err = bbdd_jrpc_dissect_notif(notif_obj, &method, &params, &error);
	if (err) {
		bbdd_err_print(&error, "monitor event");
		return 0;
	}

	bbdd_c_monitor_handle_notif(method, params);
	return 0;
}

static int bbdd_c_monitor_handshake_done_cb(struct json_object *result,
					    void *data, char **)
{
	struct bbdd_c_monitor_ctx *mctx = data;

	assert(json_object_get_type(result) == json_type_null);

	mctx->tkn->obj_cb = bbdd_c_monitor_recv_cb;
	assert(mctx->tkn->data == mctx);
	return 0;
}

static int bbdd_c_monitor_handshake_cb(struct bbdd_util_ssk_json_tkn *,
				       struct json_object *notif_obj,
				       void *data, char **error)
{
	struct bbdd_c_monitor_ctx *mctx = data;

	/* This gets called to handle the initial empty message. This could be
	 * an error message, in which case __bbdd_c_ctl_recv_obj() bails out.
	 * Otherwise the handshake is done, and we switch to the normal monitor
	 * message handler in the above callback. */
	return __bbdd_c_ctl_recv_obj(notif_obj,
				     bbdd_c_monitor_handshake_done_cb, mctx,
				     json_type_null, &mctx->ec, error);
}

static struct json_object *
bbdd_c_monitor_build_request(struct bbdd_mon_topics topics, int id,
			     char **error)
{
	struct json_object *topics_arr;
	struct json_object *params_obj;
	struct json_object *request;

	request = bbdd_jrpc_new_request(id, "monitor-subscribe");
	if (request == NULL)
		goto err;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto put_request;

	topics_arr = json_object_new_array();
	if (topics_arr == NULL)
		goto put_params;

#define ADD_ENABLED_TOPIC(NAME, ALL)					\
	if (topics.enabled[BBDD_MON_TOPIC_ ## NAME]) {			\
		struct json_object *s = json_object_new_string(#NAME);	\
		if (s == NULL || json_object_array_add(topics_arr, s)) { \
			json_object_put(s);				\
			goto put_topics;				\
		}							\
	}
	BBDD_MON_TOPICS(ADD_ENABLED_TOPIC)
#undef ADD_ENABLED_TOPIC

	if (bbdd_jrpc_append_obj(params_obj, "topics", &topics_arr))
		goto put_topics;

	if (bbdd_jrpc_append_obj(request, "params", &params_obj))
		goto put_params;

	return request;

put_topics:
	json_object_put(topics_arr);
put_params:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
err:
	bbdd_err_fmt(error, "Failed to build monitor request: %m");
	return NULL;
}

static int bbdd_c_ssk_monitor_jrpc_rx_cb(struct bbdd_ssk_peer *peer,
					 const char *buf, size_t len,
					 void *data, char **error)
{
	struct bbdd_c_monitor_ctx *mctx = data;

	return bbdd_util_ssk_json_tkn_rx_cb(peer, buf, len, mctx->tkn, error);
}

static void bbdd_c_ssk_monitor_jrpc_done_cb(struct bbdd_ssk_peer *, void *data)
{
	struct bbdd_c_monitor_ctx *mctx = data;

	bbdd_poll_request_quit(mctx->pctx);
}

static struct bbdd_ec
bbdd_c_monitor_jrpc(const struct bbdd_mon_topics *int_topics,
		    struct bbdd_mon_topics remote_topics)
{
	struct bbdd_c_monitor_ctx mctx = {
		.ec = bbdd_ec_failure,
	};
	struct json_object *request;
	struct bbdd_sockaddr bsa;
	struct bbdd_ssk_cbs cbs;
	const char *request_str;
	const int id = 1;
	int rc = -ENOMEM;
	char *error;

	request = bbdd_c_monitor_build_request(remote_topics, id, &error);
	if (request == NULL)
		goto err;

	request_str = json_object_to_json_string(request);
	if (request_str == NULL) {
		bbdd_err_fmt(&error, "Failed to serialize JSON object");
		goto put_request;
	}

	mctx.mon = bbdd_mon_create(bbdd_env.mon_eager, &error);
	if (mctx.mon == NULL)
		goto put_request;

	rc = bbdd_mon_subscribe_cb(mctx.mon, bbdd_c_monitor_dispatch, NULL,
				   *int_topics, &error);
	if (rc != 0)
		goto mon_fini;

	mctx.pctx = bbdd_poll_init(mctx.mon, &error);
	if (mctx.pctx == NULL)
		goto mon_fini;

	rc = bbdd_ctl_sockaddr(bbdd_env.sockdir, &bsa, &error);
	if (rc != 0)
		goto poll_fini;

	mctx.tkn = bbdd_util_ssk_json_tkn_create(bbdd_c_monitor_handshake_cb,
						 &mctx, &error);
	if (mctx.tkn == NULL) {
		rc = -1;
		goto poll_fini;
	}

	cbs = (struct bbdd_ssk_cbs) {
		.rx_cb = bbdd_c_ssk_monitor_jrpc_rx_cb,
		.done_cb = bbdd_c_ssk_monitor_jrpc_done_cb,
		.data = &mctx,
	};

	rc = bbdd_ssk_open_c(&mctx.ctl, mctx.pctx, &bsa, cbs, &error);
	if (rc != 0)
		goto tkn_destroy;

	rc = bbdd_poll_set_signals(mctx.pctx, &error);
	if (rc != 0)
		goto ssk_close_ctl;


	rc = bbdd_ssk_c_nq(&mctx.ctl, request_str, strlen(request_str), &error);
	if (rc != 0)
		goto unset_signals;

	rc = bbdd_poll_loop(mctx.pctx, &error);

unset_signals:
	bbdd_poll_unset_signals(mctx.pctx);
ssk_close_ctl:
	bbdd_ssk_close_c(&mctx.ctl);
tkn_destroy:
	bbdd_util_ssk_json_tkn_destroy(mctx.tkn);
poll_fini:
	bbdd_poll_fini(mctx.pctx);
mon_fini:
	bbdd_mon_destroy(mctx.mon);
put_request:
	json_object_put(request);
err:
	if (rc != 0) {
		bbdd_err_print(&error, "Communication error");
		return bbdd_ec_failure;
	}
	return mctx.ec;
}


static void bbdd_c_monitor_enable_all(struct bbdd_mon_topics *topics)
{
#define TOPIC_ON_BY_DEFAULT(NAME, ALL)			\
			[BBDD_MON_TOPIC_ ## NAME] = (ALL),

	bool on_by_default[] = {
		BBDD_MON_TOPICS(TOPIC_ON_BY_DEFAULT)
	};
	for (int i = 0; i < bbdd_mon_ntopics; i++)
		if (on_by_default[i])
			topics->enabled[i] = true;

#undef TOPIC_ON_BY_DEFAULT
}

static bool bbdd_c_monitor_enable_topic(struct bbdd_mon_topics *topics,
					const char *topic)
{
#define MATCH_TOPIC(NAME, ALL)						\
	if (strcmp(topic, #NAME) == 0) {				\
		topics->enabled[BBDD_MON_TOPIC_ ## NAME] = true;	\
		return true;						\
	}

	BBDD_MON_TOPICS(MATCH_TOPIC);
	return false;

#undef MATCH_TOPIC
}

static int bbdd_c_monitor_parse_topics(int argc, char **argv,
				       struct bbdd_mon_topics *topics)
{
	bool have_topics = false;

	while (argc > 0) {
		if (strcmp(*argv, "all") == 0) {
			have_topics = true;
			bbdd_c_monitor_enable_all(topics);
		} else {
			have_topics = true;
			if (!bbdd_c_monitor_enable_topic(topics, *argv)) {
				fprintf(stderr, "What is \"%s\"?\n", *argv);
				return -1;
			}
		}
		NEXT_ARG_FWD();
	}

	if (!have_topics)
		bbdd_c_monitor_enable_all(topics);

	return 0;
}

void bbdd_c_monitor_dispatch(struct json_object *msg, void *)
{
	struct json_object *params;
	const char *method;
	char *error;
	int err;

	err = bbdd_jrpc_dissect_notif(msg, &method, &params, &error);
	if (err) {
		bbdd_err_print(&error, "Failed to dissect monitor event");
		return;
	}

	bbdd_c_monitor_handle_notif(method, params);
}

struct bbdd_ec bbdd_c_monitor(int argc, char **argv,
			      const struct bbdd_mon_topics *int_topics)
{
	struct bbdd_mon_topics topics = {};

	if (argc > 0 && strcmp(*argv, "help") == 0) {
		bbdd_c_monitor_help();
		return bbdd_ec_success;
	}

	if (bbdd_c_monitor_parse_topics(argc, argv, &topics) < 0)
		return bbdd_ec_failure;

	return bbdd_c_monitor_jrpc(int_topics, topics);
}
