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

static int bbdd_d_jrpc_dissect_session_flag(struct json_object *flag_obj,
					    struct bbdd_c_session *sess,
					    char **error)
{
	enum json_type type = json_object_get_type(flag_obj);
	const char *str;

	if (type != json_type_string) {
		bbdd_jrpc_fmterr(error, "Session flag array element expected to be string, got %s",
				 json_type_to_name(type));
		return -1;
	}

	str = json_object_get_string(flag_obj);

#define EXPAND_MATCH(NAME, name, ...)					\
		if (strcmp(#name, str) == 0) {				\
			sess->flags[BBDD_C_SESSION_FLAG_ ## NAME] = true; \
			return 0;					\
		}
	BBDD_C_SESSION_FLAGS(EXPAND_MATCH)
#undef EXPAND_MATCH

	bbdd_jrpc_fmterr(error, "Unknown session flag `%s'", str);
	return -1;
}

static int bbdd_d_jrpc_dissect_session_flags(struct json_object *flag_array,
					     struct bbdd_c_session *sess,
					     char **error)
{
	size_t flag_array_len;
	int err;

	assert(json_object_get_type(flag_array) == json_type_array);
	flag_array_len = json_object_array_length(flag_array);

	memset(sess->flags, 0, sizeof(sess->flags));
	for (size_t i = 0; i < flag_array_len; i++) {
		struct json_object *flag_obj =
			json_object_array_get_idx(flag_array, i);

		err = bbdd_d_jrpc_dissect_session_flag(flag_obj, sess, error);
		if (err)
			return err;
	}

	return 0;
}

int bbdd_d_jrpc_dissect_params_session(struct json_object *obj,
				       struct bbdd_c_session *sess,
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
	int af;
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values,
			       ARRAY_SIZE(policy), error);
	if (rc != 0)
		return rc;

	memset(sess, 0, sizeof(*sess));

	if (seen[pol_flags] &&
	    bbdd_d_jrpc_dissect_session_flags(values[pol_flags],
					      sess, error) < 0)
		goto fail;

	af = sess->flags[BBDD_C_SESSION_FLAG_IPV6] ? AF_INET6 : AF_INET;

	if (seen[pol_src]) {
		if (bbdd_jrpc_strcpy(values[pol_src],
				     sess->src, sizeof(sess->src), error) < 0)
			goto fail;
		sess->src_af = af;
	}
	if (seen[pol_dst]) {
		if (bbdd_jrpc_strcpy(values[pol_dst],
				     sess->dst, sizeof(sess->dst), error) < 0)
			goto fail;
		sess->dst_af = af;
	}

	if (seen[pol_ifname]) {
		if (bbdd_jrpc_strcpy(values[pol_ifname],
				     sess->ifname, sizeof(sess->ifname), error) < 0)
		    goto fail;
		sess->ifname_seen = 1;
	}

#define __DISSECT(NAME, CB) do {					\
		if (seen[pol_ ## NAME]) {				\
			if (CB(values[pol_ ## NAME], &sess->NAME, error) < 0) \
				goto fail;				\
			sess->NAME ## _seen = 1;			\
		}							\
	} while (0)

#define DISSECT_U32_NON0(NAME) __DISSECT(NAME, bbdd_jrpc_get_uint32_non0)
#define DISSECT_U32(NAME) __DISSECT(NAME, bbdd_jrpc_get_uint32)
#define DISSECT_U8(NAME) __DISSECT(NAME, bbdd_jrpc_get_uint8)

	DISSECT_U32(lid);
	DISSECT_U32(min_tx);
	DISSECT_U32(min_rx);
	DISSECT_U32(min_echo_tx);
	DISSECT_U32(min_echo_rx);
	DISSECT_U32(hold_time);
	DISSECT_U8(ttl);
	DISSECT_U8(detect_mult);
	DISSECT_U32_NON0(ifindex);

#undef DISSECT_U8
#undef DISSECT_U32
#undef DISSECT_U32_NON0
#undef __DISSECT

	return 0;

fail:
	return -1;
}

static bool bbdd_d_addr_in4_zero(const struct sockaddr_in *sin)
{
	return sin->sin_addr.s_addr == 0;
}

static bool bbdd_d_addr_in6_zero(const struct sockaddr_in6 *sin6)
{
	struct in6_addr empty = {};

	return memcmp(&sin6->sin6_addr, &empty, sizeof(empty)) == 0;
}

static bool bbdd_d_addr_zero(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return bbdd_d_addr_in4_zero((struct sockaddr_in *) sa);
	case AF_INET6:
		return bbdd_d_addr_in6_zero((struct sockaddr_in6 *) sa);
	}

	fprintf(stderr, "warning: invalid address family `%d'\n",
		sa->sa_family);
	return false;
}

static void bbdd_d_sockaddr_in4_ntop(socklen_t size;
				     const struct sockaddr_in *sin,
				     char dst[size], socklen_t size)
{
	inet_ntop(sin->sin_family, &sin->sin_addr, dst, size);
}

static void bbdd_d_sockaddr_in6_ntop(socklen_t size;
				     const struct sockaddr_in6 *sin6,
				     char dst[size], socklen_t size)
{
	inet_ntop(sin6->sin6_family, &sin6->sin6_addr, dst, size);
}

static void bbdd_d_sockaddr_ntop(socklen_t size;
				 const struct sockaddr *sa,
				 char dst[size], socklen_t size)
{
	switch (sa->sa_family) {
	case AF_INET:
		return bbdd_d_sockaddr_in4_ntop((struct sockaddr_in *) sa,
						dst, size);
	case AF_INET6:
		return bbdd_d_sockaddr_in6_ntop((struct sockaddr_in6 *) sa,
						dst, size);
	}

	snprintf(dst, size, "[af %d?]", sa->sa_family);
}

static void bbdd_d_session_from_soft(struct bbdd_c_session *sess,
				     const struct bfd_session *bs)
{
	*sess = (struct bbdd_c_session){};

	sess->flags[BBDD_C_SESSION_FLAG_MULTIHOP] = bs->bs_multihop;
	sess->flags[BBDD_C_SESSION_FLAG_DEMAND] = bs->bs_demand;
	sess->flags[BBDD_C_SESSION_FLAG_CBIT] = bs->bs_cbit;
	sess->flags[BBDD_C_SESSION_FLAG_ECHO] = bs->bs_echo;
	sess->flags[BBDD_C_SESSION_FLAG_IPV6] = !bs->bs_ipv4;
	sess->flags[BBDD_C_SESSION_FLAG_PASSIVE] = bs->bs_passive;
	sess->flags[BBDD_C_SESSION_FLAG_SHUTDOWN] = bs->bs_admin_shutdown;

	if (!bbdd_d_addr_zero(&bs->bs_src.bs_src_sa)) {
		bbdd_d_sockaddr_ntop(&bs->bs_src.bs_src_sa,
				     sess->src, sizeof(sess->src));
		sess->src_af = bs->bs_src.bs_src_sa.sa_family;
	}
	if (!bbdd_d_addr_zero(&bs->bs_dst.bs_dst_sa)) {
		bbdd_d_sockaddr_ntop(&bs->bs_dst.bs_dst_sa,
				     sess->dst, sizeof(sess->dst));
		sess->dst_af = bs->bs_dst.bs_dst_sa.sa_family;
	}

	if (bs->bs_ifname[0] != '\0') {
		strncpy(sess->ifname, bs->bs_ifname, sizeof(sess->ifname));
		sess->ifname_seen = 1;
	}

#define ASSIGN(TO, FROM) do {			\
		TO = FROM;			\
		TO ## _seen = 1;		\
	} while (0)

#define ASSIGN_NON0(TO, FROM) do {		\
		if (FROM)			\
			ASSIGN(TO, FROM);	\
	} while (0)

	ASSIGN(sess->lid, bs->bs_lid);
	ASSIGN_NON0(sess->min_tx, bs->bs_cur_tx); // xxx what's with the cur/non-cur field duality?
	ASSIGN_NON0(sess->min_rx, bs->bs_cur_rx);
	ASSIGN_NON0(sess->min_echo_rx, bs->bs_etx);
	ASSIGN_NON0(sess->min_echo_rx, bs->bs_cur_erx);
	ASSIGN_NON0(sess->hold_time, bs->bs_hold);
	ASSIGN_NON0(sess->ttl, bs->bs_minttl);
	ASSIGN_NON0(sess->detect_mult, bs->bs_dmultiplier);
	ASSIGN_NON0(sess->ifindex, bs->bs_ifindex);

#undef ASSIGN_NON0
#undef ASSIGN
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
		struct bbdd_c_session sess;

		bbdd_d_session_from_soft(&sess, bs);

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

static int bbdd_d_session_to_frr(const struct bbdd_c_session *sess,
				 struct bfddp_session *bds,
				 char **error)
{
	int err;

	*bds = (struct bfddp_session){};

#define EXPAND_FLAG(NAME, name, ...)		\
		[BBDD_C_SESSION_FLAG_ ## NAME] = SESSION_ ## NAME,

	uint32_t bfddp_flags[BBDD_C_SESSION_NFLAGS] = {
		BBDD_C_SESSION_FLAGS(EXPAND_FLAG)
	};

#undef EXPAND_FLAG

	for (int i = 0; i < BBDD_C_SESSION_NFLAGS; i++)
		if (sess->flags[i])
			bds->flags |= bfddp_flags[i];

	if (sess->src_af) {
		err = bbdd_inet_pton(sess->src_af, sess->src, &bds->src, error);
		if (err)
			return err;
	}
	if (sess->dst_af) {
		err = bbdd_inet_pton(sess->dst_af, sess->dst, &bds->dst, error);
		if (err)
			return err;
	}
	if (sess->ifname_seen)
		strncpy(bds->ifname, sess->ifname, sizeof(bds->ifname));

#define ASSIGN(FIELD)					\
		if (sess->FIELD ## _seen)		\
			bds->FIELD = sess->FIELD;

	ASSIGN(lid);
	ASSIGN(min_tx);
	ASSIGN(min_rx);
	ASSIGN(min_echo_rx);
	ASSIGN(min_echo_rx);
	ASSIGN(hold_time);
	ASSIGN(ttl);
	ASSIGN(detect_mult);
	ASSIGN(ifindex);

#undef ASSIGN

	return 0;
}

static void bbdd_d_handle_session_add(struct events_ctx *ec,
				      struct bfddp_ctx *bctx,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session sess;
	struct bfddp_session bds;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, &sess, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	rc = bbdd_d_session_to_frr(&sess, &bds, &error);
	if (rc != 0)  {
		bbdd_d_respond_interr(peer, id, error);
		free(error);
		return;
	}

	bfddp_process_edit_session(ec, bctx, &bds);
	bbdd_d_respond_empty(peer, id);
}

/* Returns < 0 for errors, 0 for not a match, 1 for match. */
static int bbdd_d_session_addr_matches(int a_af, const char a[INET6_ADDRSTRLEN],
				       int b_af, const char b[INET6_ADDRSTRLEN],
				       char **error)
{
	struct in6_addr a_addr = {};
	struct in6_addr b_addr = {};
	int rc;

	if (a_af != b_af)
		return 0;

	rc = bbdd_inet_pton(a_af, a, &a_addr, error);
	if (rc < 0)
		return rc;

	rc = bbdd_inet_pton(b_af, b, &b_addr, error);
	if (rc < 0)
		return rc;

	if (memcmp(&a_addr, &b_addr, sizeof(a_addr)) != 0)
		return 0;

	return 1;
}

/* Returns < 0 for errors, 0 for not a match, 1 for match. */
static int bbdd_d_session_matches(const struct bbdd_c_session *q,
				  const struct bfd_session *bs,
				  char **error)
{
	struct bbdd_c_session sess;
	int rc;

	bbdd_d_session_from_soft(&sess, bs);

	for (int i = 0; i < BBDD_C_SESSION_NFLAGS; i++)
		if (q->flags[i] && !sess.flags[i])
			return false;

	if (q->src_af) {
		rc = bbdd_d_session_addr_matches(q->src_af, q->src,
						 sess.src_af, sess.src,
						 error);
		if (rc <= 0)
			return rc;
	}

	if (q->dst_af) {
		rc = bbdd_d_session_addr_matches(q->dst_af, q->dst,
						 sess.dst_af, sess.dst,
						 error);
		if (rc <= 0)
			return rc;
	}

	if (q->ifname_seen && (!sess.ifname_seen ||
			       strcmp(q->ifname, sess.ifname) != 0))
		return 0;

#define FIELD(NAME)						\
	if (q->NAME ## _seen && (!sess.NAME ## _seen ||		\
				 q->NAME != sess.NAME))		\
		return 0

	FIELD(lid);
	FIELD(min_tx);
	FIELD(min_rx);
	FIELD(min_echo_tx);
	FIELD(min_echo_rx);
	FIELD(hold_time);
	FIELD(ttl);
	FIELD(detect_mult);
	FIELD(ifindex);
#undef FIELD

	return 1;
}

static void bbdd_d_handle_session_del(struct events_ctx *,
				      struct bfddp_ctx *,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bfd_session *bs = NULL;
	struct bbdd_c_session sess;
	uint32_t lid;
	bool seen;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, &sess, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	seen = false;
	while ((bs = bfd_sessions_walk(bs))) {
		rc = bbdd_d_session_matches(&sess, bs, &error);
		if (rc < 0) {
			bbdd_d_respond_interr(peer, id, error);
			free(error);
			return;
		}
		if (rc == 1) {
			if (seen) {
				bbdd_d_respond_invalid_params(peer, id,
							      "The deletion request matches more than one session");
				return;
			}
			lid = bs->bs_lid;
			seen = true;
		}
	}
	if (!seen) {
		bbdd_d_respond_invalid_params(peer, id,
					      "The deletion request matches no session");
		return;
	}

	bs = bfd_session_lookup(lid);
	if (bs == NULL) {
		bbdd_d_respond_invalid_params(peer, id,
					      "The deletion request matched an already-deleted session");
		return;
	}

	bfddp_session_free(&bs, NULL);
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
		{"session-del", bbdd_d_handle_session_del},
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
