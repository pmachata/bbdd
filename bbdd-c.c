// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
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
#include "bbdd-util.h"

/* For carrying state information decoded from RPC. Most local session-specific
 * information is carried in bbdd_c_session. This contains the state & diag bits
 * for local session, and known remote session configuration. */
struct bbdd_c_session_state {
	struct bbdd_d_session_state_end local;
	struct bbdd_d_session_data remote;

	/* Optional fields added by bbdd-bpf. */
	bool poll_pending_seen;
	bool poll_pending;
};

#define BBDD_D_DEFAULT_DPLANEADDR "unix:/var/run/frr/bfdd_dplane.sock"

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

static int bbdd_c_global_stats_get_jrpc_result(struct json_object *response,
					       const int id)
{
	struct json_object *result;

	if (!bbdd_c_response_extract_result(response, id, json_type_object,
					    &result))
		return -1;

	if (bbdd_c_result_show_json(result))
		goto put_result;

	printf("global:\n");
	bbdd_c_print_stats_obj(result);

put_result:
	json_object_put(result);
	return 0;
}

static int bbdd_c_global_stats_get_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	const int id = 1;
	int err;

	request = bbdd_jrpc_new_request(id, "global-stats-diag");
	if (request == NULL)
		return -1;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	err = bbdd_c_global_stats_get_jrpc_result(response, id);
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}


static int bbdd_c_session_act_jrpc_result(struct json_object *response,
					  const char *method,
					  const int id)

{
	struct json_object *result;

	if (!bbdd_c_response_extract_result(response, id,
					   json_type_null, &result))
		return -1;

	if (bbdd_c_result_show_json(result))
		goto put_result;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "`%s' was handled by the daemon\n", method);

put_result:
	json_object_put(result);
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
		bbdd_util_fmterr(error, "Invalid session state `%s'",
				 state_str);
		return rc;
	}

	diag_str = json_object_get_string(values[pol_diag]);
	rc = bbdd_d_bfd_diag_from_str(diag_str, &data->state.diag);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Invalid session diag `%s'",
				 diag_str);
		return rc;
	}

#define __DISSECT(NAME, CB) do {					\
		if (seen[pol_ ## NAME]) {				\
			if (CB(values[pol_ ## NAME], &data->NAME, error) < 0) \
				return -1;				\
		}							\
	} while (0)
#define DISSECT_U32(NAME) __DISSECT(NAME, bbdd_jrpc_get_uint32)
#define DISSECT_U8(NAME) __DISSECT(NAME, bbdd_jrpc_get_uint8)

	DISSECT_U32(discr);
	DISSECT_U8(detect_mult);
	DISSECT_U32(min_tx_us);
	DISSECT_U32(min_rx_us);

#undef DISSECT_U8
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
bbdd_c_jrpc_dissect_session_state(struct json_object *obj,
				  struct bbdd_c_session_state *state,
				  char **error)
{
	enum {
		pol_local,
		pol_remote,
		pol_poll_pending,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_local] = { .key = "local", .type = json_type_object,
				.required = true},
		[pol_remote] = { .key = "remote", .type = json_type_object,
				 .required = true},
		[pol_poll_pending] = { .key = "poll_pending",
				       .type = json_type_boolean,
				       .required = false},
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	rc = bbdd_c_jrpc_dissect_session_state_local(values[pol_local],
						     &state->local, error);
	if (rc != 0)
		return rc;

	rc = bbdd_c_jrpc_dissect_session_state_remote(values[pol_remote],
						      &state->remote, error);
	if (rc != 0)
		return rc;

	if (seen[pol_poll_pending]) {
		state->poll_pending_seen = true;
		state->poll_pending =
			json_object_get_boolean(values[pol_poll_pending]);
	}

	return 0;
}

static int bbdd_c_jrpc_dissect_session_list(struct json_object *obj,
					    struct bbdd_c_session *sess,
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

	rc = bbdd_d_jrpc_dissect_session_one(values[pol_data], sess, error);
	if (rc != 0)
		return rc;

	rc = bbdd_c_jrpc_dissect_session_state(values[pol_state], state,
					       error);
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
		bbdd_util_fmterr(error, "Couldn't allocate sessions: %m");
		return -1;
	}

	states = calloc(sess_array_len, sizeof(*states));
	if (states == NULL) {
		bbdd_util_fmterr(error, "Couldn't allocate session states: %m");
		goto free_sessions;
	}

	for (size_t i = 0; i < sess_array_len; i++) {
		struct json_object *sess_obj =
			json_object_array_get_idx(sess_array, i);
		struct bbdd_c_session *session = &sessions[i];
		struct bbdd_c_session_state *state = &states[i];
		int err;

		err = bbdd_c_jrpc_dissect_session_list(sess_obj, session,
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

static void bbdd_c_show_time_us(const char *label, uint32_t us)
{
	if (bbdd_env.numeric) {
		printf("%s %u ", label, us);
		return;
	}
	if (us % 1000000 == 0)
		printf("%s %us ", label, us / 1000000);
	else if (us % 1000 == 0)
		printf("%s %ums ", label, us / 1000);
	else
		printf("%s %uus ", label, us);
}

static void
bbdd_c_session_show_data(const struct bbdd_d_session_data *data)
{
	printf("discr %u ", data->discr);
	printf("detect-mult %u ", data->detect_mult);
	bbdd_c_show_time_us("min-tx", data->min_tx_us);
	bbdd_c_show_time_us("min-rx", data->min_rx_us);
	bbdd_c_session_show_state_end(&data->state);
}

static void bbdd_c_session_show_one(struct bbdd_c_session *sess,
				    struct bbdd_c_session_state *state)
{
	bool seen = false;
	if (sess->discr_seen) {
		printf("discr %u ", sess->discr);
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
	if (sess->min_tx_us_seen) {
		bbdd_c_show_time_us("min-tx", sess->min_tx_us);
		seen = true;
	}
	if (sess->min_rx_us_seen) {
		bbdd_c_show_time_us("min-rx", sess->min_rx_us);
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

	/* Prefer ifname to ifindex, but show both in verbose mode. */
	if (sess->netif.name_seen) {
		printf("ifname %s ", sess->netif.name);
		seen = true;
	}
	if ((!sess->netif.name_seen || bbdd_env.verbosity > 0) &&
	    sess->netif.ifindex_seen) {
		printf("ifindex %u ", sess->netif.ifindex);
		seen = true;
	}

	/* Prefer VRF name to table ID, but show both in verbose mode. */
	if (sess->vrf.netif.name_seen) {
		printf("vrf %s ", sess->vrf.netif.name);
		seen = true;
	}
	if ((!sess->vrf.netif.name_seen || bbdd_env.verbosity > 0) &&
	    sess->vrf.table_seen) {
		printf("table %d ", sess->vrf.table);
		seen = true;
	}

	if (!seen)
		printf("(session without data)");

	printf(": local ");
	bbdd_c_session_show_state_end(&state->local);
	printf("remote ");
	bbdd_c_session_show_data(&state->remote);

	if (state->poll_pending_seen && state->poll_pending)
		printf("poll-pending ");

	printf("\n");
}

static int bbdd_c_session_show_jrpc_result(struct json_object *response,
					   const char *, const int id)
{
	struct json_object *result;
	struct bbdd_c_session *sessions;
	struct bbdd_c_session_state *states;
	size_t num_sessions;
	char *error;
	int err;

	if (!bbdd_c_response_extract_result(response, id,
					    json_type_object, &result))
		return -1;

	if (bbdd_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	err = bbdd_c_session_show_jrpc_dissect(result, &sessions, &states,
					       &num_sessions, &error);
	if (err != 0) {
		fprintf(stderr, "Invalid session object: %s\n", error);
		free(error);
		goto put_result;
	}

	for (size_t i = 0; i < num_sessions; i++)
		bbdd_c_session_show_one(&sessions[i], &states[i]);
	if (num_sessions == 0 && bbdd_env.verbosity > 0)
		printf("(no sessions)\n");
	free(sessions);
	free(states);

put_result:
	json_object_put(result);
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

static int bbdd_c_session_stats_jrpc_result(struct json_object *response,
					    const char *, const int id)
{
	struct json_object *result;
	char *error = NULL;
	int err = 0;

	if (!bbdd_c_response_extract_result(response, id, json_type_object,
					    &result))
		return -1;

	if (bbdd_c_result_show_json(result))
		goto put_result;

	err = bbdd_c_session_stats_dissect_result(result, &error);
	if (err != 0) {
		fprintf(stderr, "%s\n", error);
		free(error);
	}

put_result:
	json_object_put(result);
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
	int (*show)(struct json_object *, const char *method, int id);
} const bbdd_c_session_commands[] = {
	{
		.name = "add",
		.allow_change = true,
		.rpc = "session-add",
		.show = bbdd_c_session_act_jrpc_result,
	},
	{
		.name = "set",
		.allow_bulk = true,
		.allow_query = true,
		.allow_change = true,
		.rpc = "session-set",
		.show = bbdd_c_session_act_jrpc_result,
	},
	{
		.name = "del",
		.allow_bulk = true,
		.allow_query = true,
		.rpc = "session-del",
		.show = bbdd_c_session_act_jrpc_result,
	},
	{
		.name = "show",
		.allow_query = true,
		.rpc = "session-show",
		.show = bbdd_c_session_show_jrpc_result,
	},
	{
		.name = "stats",
		.allow_diag = true,
		.allow_query = true,
		.rpc = "session-stats",
		.rpc_diag = "session-stats-diag",
		.show = bbdd_c_session_stats_jrpc_result,
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
		"       bulk		-- request is allowed to impact >1 session\n"
		"       diag		-- request diagnostic stats instead of operational ones\n"
		"\n"
		"where	QUERY-PARAMS := PARAMS	-- parameters for session select\n"
		"	SET-PARAMS := PARAMS	-- adjusted / new session parameters\n"
		"	PARAMS ::= PARAM [ PARAMS ]\n"
		"	PARAM ::= { KEY VALUE | [ no ] FLAG }\n"
		"	KEY ::= { discr | src | dst | min-tx | min-rx | hold-time | ttl |"
		"	          detect-mult | ifname | ifindex | vrf | table }\n"
		"	FLAG ::= { multihop | demand | cbit | ipv6 | passive | shutdown }\n"
		"	no FLAG		-- set the flag to negative value"
		"\n"
		"Parameter KEY and VALUE details:\n"
		"	discr U32 	-- session discriminator\n"
		"	src ADDR	-- source address\n"
		"	dst ADDR	-- destination address\n"
		"	min-tx TIME	-- minimum tx interval (e.g. 100us, 10ms, 1s)\n"
		"	min-rx TIME	-- minimum rx interval (e.g. 100us, 10ms, 1s)\n"
		"	hold-time U32	-- session start wait time in miliseconds\n"
		"	ttl U8		-- minimum packet TTL\n"
		"	detect-mult U8	-- detection multiplier\n"
		"	ifname STR	-- interface name\n"
		"	ifindex U32	-- interface index\n"
		"	vrf STR		-- VRF interface name\n"
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
		"	demand		-- demand mode\n"
		"	cbit		-- control-plane independent\n"
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

int bbdd_c_global(int argc, char **argv)
{
	struct bbdd_c_session_flag diag = {};
	bool seen_stats = false;
	int rc;

	while (argc > 0) {
		if (strcmp(*argv, "stats") == 0) {
			if (seen_stats) {
				fprintf(stderr, "Duplicate `stats'.\n");
				return -1;
			}
			NEXT_ARG_FWD();
			seen_stats = true;
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			bbdd_c_global_stats_help();
			return 0;
		}

		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "diag", &diag))) {
			if (rc > 0)
				continue;
			return rc;
		}

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	if (!seen_stats) {
		fprintf(stderr, "No command given.\n");
		return -1;
	}

	if (!diag.seen || !diag.value) {
		fprintf(stderr, "Only `diag' stats are currently supported.\n");
		return -1;
	}

	return bbdd_c_global_stats_get_jrpc();
}

static int bbdd_c_parse_u8(const char *str, void *ret, const char *what)
{
	uint8_t *u8_ret = ret;
	char *error;
	int rc;

	rc = bbdd_sock_parse_u8(str, u8_ret, what, &error);
	if (rc != 0)
		bbdd_util_printerr(&error, NULL);
	return rc;
}

static int bbdd_c_parse_u32(const char *str, void *ret, const char *what)
{
	uint32_t *u32_ret = ret;
	char *error;
	int rc;

	rc = bbdd_sock_parse_u32(str, u32_ret, what, &error);
	if (rc != 0)
		bbdd_util_printerr(&error, NULL);
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

static int __bbdd_c_parse_time_us(const char *str, uint32_t *ret,
				  const char *what)
{
	unsigned long long val;
	uint32_t mult;
	char *end;

	val = strtoull(str, &end, 10);
	if (end == str) {
		fprintf(stderr, "Can't parse %s `%s': not a valid number.\n",
			what, str);
		return -1;
	}
	if (val <= 0 || val > UINT32_MAX) {
	oob:
		fprintf(stderr, "Can't parse %s `%s': value out of bounds (0, uint32_max].\n",
			what, str);
		return -1;
	}

	if (strcmp(end, "us") == 0 || *end == '\0') {
		mult = 1;
	} else if (strcmp(end, "ms") == 0) {
		mult = 1000;
	} else if (strcmp(end, "s") == 0) {
		mult = 1000000;
	} else {
		fprintf(stderr, "Can't parse %s `%s': unknown unit `%s' (use us, ms, s).\n",
			what, str, end);
		return -1;
	}

	if (val > UINT32_MAX / mult)
		goto oob;

	*ret = (uint32_t)(val * mult);
	return 0;
}

static int bbdd_c_parse_time_us(const char *str, void *ret, const char *what)
{
	return __bbdd_c_parse_time_us(str, ret, what);
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

static int bbdd_c_enomem(void)
{
	fprintf(stderr, "Failed to form RPC request: %m");
	return -ENOMEM;
}

struct json_object *bbdd_c_jrpc_session_obj(const struct bbdd_c_session *sess)
{
	struct json_object *params_obj;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto err;

	for (int i = 0; i < bbdd_c_session_nflags; i++) {
		const char *flag_name = bbdd_c_session_flag_names[i];
		const struct bbdd_c_session_flag *flag = &sess->flags.flags[i];

		if (!flag->seen)
			continue;

		if (bbdd_jrpc_append_bool(params_obj, flag_name, flag->value))
			goto put_params_obj;
	}

	if ((sess->discr_seen &&
	     bbdd_jrpc_append_int(params_obj, "discr", sess->discr)) ||
	    (sess->src_af &&
	     bbdd_jrpc_append_str(params_obj, "src", sess->src)) ||
	    (sess->dst_af &&
	     bbdd_jrpc_append_str(params_obj, "dst", sess->dst)) ||
	    (sess->min_tx_us_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_tx_us", sess->min_tx_us)) ||
	    (sess->min_rx_us_seen &&
	     bbdd_jrpc_append_int(params_obj, "min_rx_us", sess->min_rx_us)) ||
	    (sess->hold_time_seen &&
	     bbdd_jrpc_append_int(params_obj, "hold_time", sess->hold_time)) ||
	    (sess->ttl_seen &&
	     bbdd_jrpc_append_int(params_obj, "ttl", sess->ttl)) ||
	    (sess->detect_mult_seen &&
	     bbdd_jrpc_append_int(params_obj, "detect_mult",
				  sess->detect_mult)) ||
	    (sess->netif.ifindex_seen &&
	     bbdd_jrpc_append_int(params_obj, "ifindex", sess->netif.ifindex)) ||
	    (sess->netif.name_seen &&
	     bbdd_jrpc_append_str(params_obj, "ifname", sess->netif.name)) ||
	    (sess->vrf.netif.name_seen &&
	     bbdd_jrpc_append_str(params_obj, "vrf", sess->vrf.netif.name)) ||
	    (sess->vrf.table_seen &&
	     bbdd_jrpc_append_int(params_obj, "vrf_table", sess->vrf.table)))
		goto put_params_obj;

	return params_obj;

put_params_obj:
	json_object_put(params_obj);
err:
	bbdd_c_enomem();
	return NULL;
}

static int bbdd_c_session_jrpc(const struct bbdd_c_session_command *command,
			       const struct bbdd_c_session *select,
			       const struct bbdd_c_session *change,
			       struct bbdd_c_session_flag bulk,
			       struct bbdd_c_session_flag diag)
{
	struct json_object *select_obj = NULL;
	struct json_object *change_obj = NULL;
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	const char *method;
	const int id = 1;
	int err;

	if (command->allow_query) {
		select_obj = bbdd_c_jrpc_session_obj(select);
		if (select_obj == NULL)
			return -1;
	}

	if (command->allow_change) {
		change_obj = bbdd_c_jrpc_session_obj(change);
		if (change_obj == NULL) {
			err = -ENOMEM;
			goto put_select;
		}
	}

	if (diag.seen && diag.value)
		method = command->rpc_diag;
	else
		method = command->rpc;

	assert(method != NULL);

	request = bbdd_jrpc_new_request(id, method);
	if (request == NULL) {
		err = -1;
		goto put_select_change;
	}

	params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = bbdd_c_enomem();
		goto put_request;
	}

	if (select_obj != NULL &&
	    json_object_object_add(params_obj, "select", select_obj)) {
		err = bbdd_c_enomem();
		goto put_params_obj;
	}
	select_obj = NULL;

	if (change_obj != NULL &&
	    json_object_object_add(params_obj, "change", change_obj)) {
		err = bbdd_c_enomem();
		goto put_params_obj;
	}
	change_obj = NULL;

	if (bulk.seen && bulk.value &&
	    bbdd_jrpc_append_bool(params_obj, "bulk", bulk.value)) {
		err = bbdd_c_enomem();
		goto put_params_obj;
	}

	if (json_object_object_add(request, "params", params_obj)) {
		err = bbdd_c_enomem();
		goto put_params_obj;
	}
	params_obj = NULL;

	response = bbdd_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	err = command->show(response, method, id);
	if (err)
		goto put_response;

	err = 0;

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

	return 0;
}

int bbdd_c_session(int argc, char **argv)
{
	struct bbdd_c_session select = {};
	struct bbdd_c_session change = {};
	struct bbdd_c_session *sess = &select;
	bool seen_arg = false;
	struct bbdd_c_session_flag bulk = {};
	struct bbdd_c_session_flag diag = {};
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
				return -1;
			}

			command = command2;
			arg_was_command = true;

			if (!command->allow_query && seen_arg) {
				fprintf(stderr, "`%s' used with session query parameters\n",
					command->name);
				return -1;
			}

			if (command->allow_change)
				sess = &change;
			else
				sess = NULL;

			NEXT_ARG_FWD();
			break;
		}

		if (arg_was_command)
			continue;

		if (strcmp(*argv, "help") == 0) {
			bbdd_c_session_help();
			return 0;
		}

		if (sess == NULL) {
			fprintf(stderr, "`%s' used with session change parameters\n",
				command->name);
			return -1;
		}

		seen_arg = true;

		if ((rc = bbdd_c_parse_kw_flag(&argc, &argv, "multihop",
					       &sess->flags.multihop)) ||
		    (rc = bbdd_c_parse_kw_flag(&argc, &argv, "cbit",
					       &sess->flags.cbit)) ||
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
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "discr",
					      &sess->discr,
					      &sess->discr_seen)) ||
		    (rc = bbdd_c_parse_kw_time_us(&argc, &argv, "min-tx",
						  &sess->min_tx_us,
						  &sess->min_tx_us_seen)) ||
		    (rc = bbdd_c_parse_kw_time_us(&argc, &argv, "min-rx",
						  &sess->min_rx_us,
						  &sess->min_rx_us_seen)) ||
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
					      &sess->netif.ifindex,
					      &sess->netif.ifindex_seen)) ||
		    (rc = bbdd_c_parse_kw_ifname(&argc, &argv, "ifname",
						 sess->netif.name,
						 &sess->netif.name_seen)) ||
		    (rc = bbdd_c_parse_kw_ifname(&argc, &argv, "vrf",
						 sess->vrf.netif.name,
						 &sess->vrf.netif.name_seen)) ||
		    (rc = bbdd_c_parse_kw_u32(&argc, &argv, "table",
					      &sess->vrf.table,
					      &sess->vrf.table_seen)) ||

		    (command == NULL &&
		     (rc = bbdd_c_parse_kw_flag(&argc, &argv, "bulk", &bulk))) ||
		    (command == NULL &&
		     (rc = bbdd_c_parse_kw_flag(&argc, &argv, "diag", &diag)))) {
			if (rc > 0)
				continue;
			return rc;
		}

		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	if (command == NULL) {
		fprintf(stderr, "No command given.\n");
		return -1;
	}
	if (bulk.seen && !command->allow_bulk) {
		fprintf(stderr, "`bulk' not supported for `%s'.\n",
			command->name);
		return -1;
	}
	if (diag.seen && !command->allow_diag) {
		fprintf(stderr, "`diag' not supported for `%s'.\n",
			command->name);
		return -1;
	}

	if (bbdd_c_session_check_params(&select) < 0 ||
	    bbdd_c_session_check_params(&change) < 0)
		return -1;

	return bbdd_c_session_jrpc(command, &select, &change, bulk, diag);
}

static int bbdd_c_bfdd_connect_jrpc(const char *proto,
				    const char *addr,
				    const char *port)
{
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	request = bbdd_jrpc_new_request(id, "bfdd-connect");
	if (request == NULL)
		return -1;

	params_obj = json_object_new_object();
	if (params_obj == NULL)
		goto put_request;

	if (bbdd_jrpc_object_add_str(params_obj, "proto", proto) != 0 ||
	    bbdd_jrpc_object_add_str(params_obj, "addr", addr) != 0 ||
	    (port != NULL &&
	     bbdd_jrpc_object_add_str(params_obj, "port", port))) {
		err = bbdd_c_enomem();
		goto put_params_obj;
	}

	if (json_object_object_add(request, "params", params_obj) != 0) {
		err = bbdd_c_enomem();
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

	bbdd_c_result_show_json(result);
	err = 0;

	json_object_put(result);
put_response:
	json_object_put(response);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return err;
}

static void bbdd_c_bfdd_connect_help(void)
{
	fprintf(stderr, "%s",
		"Usage: bbdd bfdd connect [TYPE:ADDRESS[:PORT]]\n"
		"TYPE ::= {ipv4 | ipv6 | unix}\n"
		"Default connect address is `" BBDD_D_DEFAULT_DPLANEADDR "'.\n"
		"\n"
	);
}

static int bbdd_c_bfdd_connect(int argc, char **argv)
{
	const char *proto;
	const char *addr;
	const char *port;
	const char *arg;
	char *copy;
	char *error;
	int rc;

	if (!argc) {
		arg = BBDD_D_DEFAULT_DPLANEADDR;
	} else if (strcmp(*argv, "help") == 0) {
		bbdd_c_bfdd_connect_help();
		return 0;
	} else {
		arg = *argv;
	}

	copy = strdup(arg);
	rc = bbdd_sock_split_addr_proto(copy, &proto, &addr, &port, &error);
	if (rc < 0) {
		bbdd_util_printerr(&error, "bfdd connect");
		goto out;
	}

	rc = bbdd_c_bfdd_connect_jrpc(proto, addr, port);

out:
	free(copy);
	return rc;
}

static int bbdd_c_bfdd_disconnect(int argc, char **argv)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	if (argc > 0) {
		fprintf(stderr, "Usage: bbdd bfdd disconnect\n\n");
		if (strcmp(*argv, "help") == 0)
			return 0;
		else
			return -1;
	}

	request = bbdd_jrpc_new_request(id, "bfdd-disconnect");
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

	bbdd_c_result_show_json(result);
	err = 0;

	json_object_put(result);
put_request:
	json_object_put(request);
put_response:
	json_object_put(response);
	return err;
}

static int bbdd_c_bfdd_connected(int argc, char **argv)
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
			return 0;
		else
			return -1;
	}

	request = bbdd_jrpc_new_request(id, "bfdd-connected");
	if (request == NULL)
		return -1;

	response = bbdd_c_send_request(request);
	if (response == NULL)
		goto put_request;

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
	return err;
}

static void bbdd_c_bfdd_help(void)
{
	fprintf(stderr,
		"Usage: bbdd bfdd { connect | connected | disconnect | help }\n"
		"\n"
	);
}

int bbdd_c_bfdd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		bbdd_c_bfdd_help();
		return 0;
	} else if (strcmp(*argv, "connect") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_connect(argc, argv);
	} else if (strcmp(*argv, "connected") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_connected(argc, argv);
	} else if (strcmp(*argv, "disconnect") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd_disconnect(argc, argv);
	}

	fprintf(stderr, "What is \"%s\"?\n", *argv);
	return -1;
}
