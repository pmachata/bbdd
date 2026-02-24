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

int bbdd_d_jrpc_dissect_session_one(struct json_object *obj,
				    struct bbdd_c_session *sess,
				    bool allow_bulk,
				    char **error)
{
#define BBDD_D_SESSION_EXPAND_POL_IX(NAME, name, ...) pol_ ## name,
#define BBDD_D_SESSION_EXPAND_POLICY(NAME, name, ...) \
		[pol_ ## name] =  { .key = #name, .type = json_type_boolean },

	enum {
		BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_POL_IX)

		pol_lid,

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

		pol_bulk, /* Only valid when allow_bulk set. */
	};
	struct bbdd_jrpc_policy policy[] = {
		BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_POLICY)

		[pol_lid] =  { .key = "lid", .type = json_type_int },

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

		[pol_bulk] = { .key = "bulk", .type = json_type_boolean },
	};

#undef BBDD_D_SESSION_EXPAND_POLICY
#undef BBDD_D_SESSION_EXPAND_POL_IX

	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	size_t polsize;
	int af;
	int rc;

	polsize = ARRAY_SIZE(policy);
	if (! allow_bulk)
		polsize--;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, polsize, error);
	if (rc != 0)
		return rc;

	memset(sess, 0, sizeof(*sess));

#define BBDD_D_SESSION_EXPAND_DISSECT(NAME, name, ...)			\
		if (seen[pol_ ## name]) {				\
			sess->flags.name.seen = true;			\
			sess->flags.name.value =			\
				json_object_get_boolean(values[pol_ ## name]); \
		}

	BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_DISSECT);

#undef BBDD_D_SESSION_EXPAND_DISSECT

	af = bbdd_c_session_flag_isset(sess->flags.ipv6) ? AF_INET6 : AF_INET;
	// xxx figure out how to handle change in protocol without giving an
	// address. Maybe it needs to be forbidden. But then src address is a
	// non-mandatory argument, so can't just force the user to provide it.
	// xxx also scope ID is necessary for link-local addresses

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

	if (seen[pol_bulk])
		sess->bulk = json_object_get_boolean(values[pol_bulk]);

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

static int bbdd_d_jrpc_dissect_params_session(struct json_object *obj,
					      struct bbdd_c_session *select,
					      struct bbdd_c_session *change,
					      char **error)
{
	enum {
		pol_select,
		pol_change,
		// xxx maybe bulk should be here
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_select] = { .key = "select", .type = json_type_object },
		[pol_change] = { .key = "change", .type = json_type_object },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	if (seen[pol_select] && select == NULL) {
		bbdd_jrpc_fmterr(error, "RPC method doesn't allow session select");
		return -1;
	}
	if (seen[pol_change] && change == NULL) {
		bbdd_jrpc_fmterr(error, "RPC method doesn't allow session change");
		return -1;
	}

	if (seen[pol_select] &&
	    bbdd_d_jrpc_dissect_session_one(values[pol_select], select,
					    true, error))
		goto fail;

	if (seen[pol_change] &&
	    bbdd_d_jrpc_dissect_session_one(values[pol_change], change,
					    false, error))
		goto fail;

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
				     struct bbdd_c_session_state *state,
				     const struct bfd_session *bs)
{
	*sess = (struct bbdd_c_session){};

	/* Only mark as seen set flags. */
#define ASSIGN_FLAG(NAME, FROM)					\
		(sess->flags.NAME.value = sess->flags.NAME.seen = FROM)

	ASSIGN_FLAG(multihop, bs->bs_multihop);
	ASSIGN_FLAG(demand, bs->bs_demand);
	ASSIGN_FLAG(cbit, bs->bs_cbit);
	ASSIGN_FLAG(echo, bs->bs_echo);
	ASSIGN_FLAG(ipv6, ! bs->bs_ipv4);
	ASSIGN_FLAG(passive, bs->bs_passive);
	ASSIGN_FLAG(shutdown, bs->bs_admin_shutdown);

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

	*state = (struct bbdd_c_session_state) {
		.local = {
			.state = bs->bs_state,
			.diag = bs->bs_diag,
		},
		.remote = {
			.state = bs->bs_rstate,
			.diag = bs->bs_rdiag,
		},
	};
}

static const char *bbdd_d_strtab_val_to_str(int value, const char **tab,
					    size_t sz)
{
	if (value < 0 || (size_t)value >= sz)
		return NULL;
	return tab[value];
}

static int bbdd_d_strtab_str_to_val(const char *str, int *ret,
				    const char **tab, size_t sz)
{
	for (size_t i = 0; i < sz; i++)
		if (strcmp(tab[i], str) == 0) {
			*ret = (int) i;
			return 0;
		}

	return -EINVAL;
}

static const char *bbdd_d_jrpc_session_state_str[] = {
	[STATE_ADMINDOWN] = "admindown",
	[STATE_DOWN] = "down",
	[STATE_INIT] = "init",
	[STATE_UP] = "up",
};

const char *bbdd_d_bfd_state_to_str(enum bfd_state_value sv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_state_str);
	const char **tab = bbdd_d_jrpc_session_state_str;

	return bbdd_d_strtab_val_to_str(sv, tab, sz);
}

int bbdd_d_bfd_state_from_str(const char *str, enum bfd_state_value *sv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_state_str);
	const char **tab = bbdd_d_jrpc_session_state_str;
	int tmp;

	if (bbdd_d_strtab_str_to_val(str, &tmp, tab, sz) < 0)
		return -EINVAL;
	*sv = tmp;
	return 0;
}

static int bbdd_d_jrpc_session_state_attach_state(struct json_object *obj,
						  enum bfd_state_value sv)
{
	const char *str = bbdd_d_bfd_state_to_str(sv);

	if (str == NULL)
		return -EINVAL;
	return bbdd_jrpc_append_str(obj, "state", str);
}

static const char *bbdd_d_jrpc_session_diag_str[] = {
	[DIAG_NOTHING] = "nothing",
	[DIAG_CONTROL_EXPIRED] = "control_expired",
	[DIAG_ECHO_FAILED] = "echo_failed",
	[DIAG_DOWN] = "down",
	[DIAG_FP_RESET] = "fp_reset",
	[DIAG_PATH_DOWN] = "path_down",
	[DIAG_CONCAT_PATH_DOWN] = "concat_path_down",
	[DIAG_ADMIN_DOWN] = "admin_down",
	[DIAG_REV_CONCAT_PATH_DOWN] = "rev_concat_path_down",
};

const char *bbdd_d_bfd_diag_to_str(enum bfd_diagnostic_value sv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_diag_str);
	const char **tab = bbdd_d_jrpc_session_diag_str;

	return bbdd_d_strtab_val_to_str(sv, tab, sz);
}

int bbdd_d_bfd_diag_from_str(const char *str, enum bfd_diagnostic_value *sv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_diag_str);
	const char **tab = bbdd_d_jrpc_session_diag_str;
	int tmp;

	if (bbdd_d_strtab_str_to_val(str, &tmp, tab, sz) < 0)
		return -EINVAL;
	*sv = tmp;
	return 0;
}

static int bbdd_d_jrpc_session_state_attach_diag(struct json_object *obj,
						 enum bfd_diagnostic_value dv)
{
	const char *str = bbdd_d_bfd_diag_to_str(dv);

	if (str == NULL)
		return -EINVAL;
	return bbdd_jrpc_append_str(obj, "diag", str);
}

static struct json_object *
bbdd_d_jrpc_session_state_end(struct bbdd_c_session_state_end *state)
{
	struct json_object *entry_obj;

	/* STATE_END ::= {
	 *     "state": STRING,
	 *     "diag": STRING,
	 * }
	 */

	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		return NULL;

	if (bbdd_d_jrpc_session_state_attach_state(entry_obj, state->state) ||
	    bbdd_d_jrpc_session_state_attach_diag(entry_obj, state->diag))
		goto put_entry_obj;

	return entry_obj;

put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

static struct json_object *
bbdd_d_jrpc_session_state_obj(struct bbdd_c_session_state *state)
{
	struct json_object *entry_obj;
	struct json_object *local_obj;
	struct json_object *remote_obj;
	int rc;

	/* STATE ::= {
	 *     "local": STATE_END,
	 *     "remote": STATE_END,
	 * }
	 */
	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		return NULL;

	local_obj = bbdd_d_jrpc_session_state_end(&state->local);
	if (local_obj == NULL)
		goto put_entry_obj;

	remote_obj = bbdd_d_jrpc_session_state_end(&state->remote);
	if (remote_obj == NULL)
		goto put_local_obj;

	rc = json_object_object_add(entry_obj, "remote", remote_obj);
	if (rc != 0)
		goto put_remote_obj;
	remote_obj = NULL;

	rc = json_object_object_add(entry_obj, "local", local_obj);
	if (rc != 0)
		goto put_local_obj;
	local_obj = NULL;

	return entry_obj;

put_remote_obj:
	json_object_put(remote_obj);
put_local_obj:
	json_object_put(local_obj);
put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

static void bbdd_d_handle_session_show_do(struct bbdd_sock *peer,
					  struct json_object *id,
					  uint32_t *lids,
					  size_t nlids)
{
	struct json_object *obj;
	struct json_object *result_obj;
	struct json_object *array;
	struct json_object *entry_obj;
	struct json_object *sess_obj;
	struct json_object *state_obj;
	int rc;
	bool dumped;

	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "sessions": [ SESS, ... ]
	 *     }
	 * }
	 *
	 * Where individual SESS objects are formatted as follows:
	 *
	 * SESS ::= {
	 *     "data": DATA,
	 *     "state": STATE,
	 * }
	 *
	 * For details of the DATA objects, see
	 * bbdd_d_jrpc_dissect_params_session_one().
	 *
	 * For details of the STATE objects, see
	 * bbdd_d_jrpc_session_state_obj().
	 */

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	array = json_object_new_array();
	if (array == NULL)
		goto put_result_obj;

	dumped = false;
	for (size_t i = 0; i < nlids; i++) {
		struct bbdd_c_session sess;
		struct bbdd_c_session_state state;
		struct bfd_session *bs;

		bs = bfd_session_lookup(lids[i]);
		if (!bs)
			continue;

		dumped = true;

		bbdd_d_session_from_soft(&sess, &state, bs);

		entry_obj = json_object_new_object();
		if (entry_obj == NULL)
			goto put_array;

		state_obj = bbdd_d_jrpc_session_state_obj(&state);
		if (state_obj == NULL)
			goto put_entry_obj;

		sess_obj = bbdd_c_jrpc_session_obj(&sess);
		if (sess_obj == NULL)
			goto put_state_obj;

		rc = json_object_object_add(entry_obj, "data", sess_obj);
		if (rc != 0)
			goto put_sess_obj;
		sess_obj = NULL;

		rc = json_object_object_add(entry_obj, "state", state_obj);
		if (rc != 0)
			goto put_state_obj;
		state_obj = NULL;

		if (json_object_array_add(array, entry_obj) != 0)
			goto put_state_obj;
		entry_obj = NULL;
	}

	if (!dumped) {
		/* Not sure this can actually happen. */
		bbdd_d_respond_invalid_params(peer, id,
					      "All matching sessions went away mid request");
		goto put_array;
	}

	rc = json_object_object_add(result_obj, "sessions", array);
	if (rc != 0)
		goto put_array;

	if (json_object_object_add(obj, "result", result_obj))
		goto put_result_obj;

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_sess_obj:
	json_object_put(sess_obj);
put_state_obj:
	json_object_put(state_obj);
put_entry_obj:
	json_object_put(entry_obj);
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
				 struct bfddp_session *mask,
				 char **error)
{
	int err;

	*bds = (struct bfddp_session){};
	*mask = (struct bfddp_session){};

#define EXPAND_FLAG(NAME, name, ...)		\
		[bbdd_c_session_flag_ ## name] = htonl(SESSION_ ## NAME),

	uint32_t bfddp_flags[bbdd_c_session_nflags] = {
		BBDD_C_SESSION_FLAGS(EXPAND_FLAG)
	};

#undef EXPAND_FLAG

	for (int i = 0; i < bbdd_c_session_nflags; i++) {
		struct bbdd_c_session_flag flag = sess->flags.flags[i];
		if (flag.seen) {
			mask->flags |= bfddp_flags[i];
			if (flag.value)
				bds->flags |= bfddp_flags[i];
		}
	}

	if (sess->src_af) {
		memset(&mask->src, 0xff, sizeof(mask->src));
		err = bbdd_inet_pton(sess->src_af, sess->src, &bds->src, error);
		if (err)
			return err;
	}
	if (sess->dst_af) {
		memset(&mask->dst, 0xff, sizeof(mask->dst));
		err = bbdd_inet_pton(sess->dst_af, sess->dst, &bds->dst, error);
		if (err)
			return err;
	}
	if (sess->ifname_seen) {
		memset(mask->ifname, 0xff, sizeof(mask->ifname));
		strncpy(bds->ifname, sess->ifname, sizeof(bds->ifname));
	}

	if (sess->ttl_seen) {
		mask->ttl = 0xff;
		bds->ttl = sess->ttl;
	}

	if (sess->detect_mult_seen) {
		mask->ttl = 0xff;
		bds->detect_mult = sess->detect_mult;
	}

#define ASSIGN(FIELD) do {						\
		if (sess->FIELD ## _seen) {				\
			bds->FIELD = htonl(sess->FIELD);		\
			memset(&mask->FIELD, 0xff, sizeof(mask->FIELD)); \
		}							\
	} while (0)

	ASSIGN(lid);
	ASSIGN(min_tx);
	ASSIGN(min_rx);
	ASSIGN(min_echo_rx);
	ASSIGN(min_echo_rx);
	ASSIGN(hold_time);
	ASSIGN(ifindex);

#undef ASSIGN

	return 0;
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
	struct bbdd_c_session_state state;
	int rc;

	bbdd_d_session_from_soft(&sess, &state, bs);

	for (int i = 0; i < bbdd_c_session_nflags; i++)
		if (q->flags.flags[i].seen &&
		    q->flags.flags[i].value != sess.flags.flags[i].value)
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

static int bbdd_d_select_sessions(const struct bbdd_c_session *sess,
				  uint32_t **p_lids,
				  size_t *p_nlids,
				  char **error)
{
	struct bfd_session *bs = NULL;
	uint32_t *lids = NULL;
	size_t nlids = 0;
	size_t cap = 0;
	int rc;

	while ((bs = bfd_sessions_walk(bs))) {
		rc = bbdd_d_session_matches(sess, bs, error);
		if (rc < 0)
			return -1;
		if (rc == 0)
			continue;

		if (nlids >= cap) {
			uint32_t *new_lids;

			cap = (cap == 0) ? 8 : cap * 2;
			new_lids = realloc(lids, cap * sizeof(*lids));
			if (new_lids == NULL)
				goto oom;
			lids = new_lids;
		}
		lids[nlids++] = bs->bs_lid;
	}
	*p_lids = lids;
	*p_nlids = nlids;
	return 0;

oom:
	errno = -ENOMEM;
	bbdd_jrpc_fmterr(error, "%m");
	free(lids);
	return -1;
}

static void bbdd_d_handle_session_add(struct events_ctx *ec,
				      struct bfddp_ctx *bctx,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session sess;
	struct bfddp_session bds;
	struct bfddp_session mask;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, NULL, &sess,
						&error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	if (!sess.lid_seen) {
		sess.lid = bfd_session_gen_discriminator();
		sess.lid_seen = true;
	} else if (bfd_session_lookup(sess.lid) != NULL) {
		bbdd_d_respond_invalid_params(peer, id, "Duplicate session");
		return;
	}

	rc = bbdd_d_session_to_frr(&sess, &bds, &mask, &error);
	if (rc != 0)  {
		bbdd_d_respond_interr(peer, id, error);
		free(error);
		return;
	}

	bfddp_session_new(bctx, ec, &bds);
	bbdd_d_respond_empty(peer, id);
}

static int bbdd_d_parse_select_sessions(struct bbdd_sock *peer,
					struct json_object *params_obj,
					struct json_object *id,
					struct bbdd_c_session *select,
					struct bbdd_c_session *change,
					uint32_t **lids,
					size_t *nlids)
{
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, select, change,
						&error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, error);
		free(error);
		return -1;
	}

	rc = bbdd_d_select_sessions(select, lids, nlids, &error);
	if (rc) {
		bbdd_d_respond_interr(peer, id, error);
		free(error);
		return -1;
	}

	return 0;
}

static int bbdd_d_handle_session_check_bulk(struct bbdd_sock *peer,
					    struct json_object *id,
					    struct bbdd_c_session *select,
					    size_t nlids)
{
	if (nlids == 0) {
		bbdd_d_respond_invalid_params(peer, id,
					      "The set request matches no session");
		return -1;
	}
	if (nlids > 1 && !select->bulk) {
		bbdd_d_respond_invalid_params(peer, id,
					      "Non-bulk set request matches more than one session");
		return -1;
	}
	return 0;
}

static void bbdd_d_handle_session_set(struct events_ctx *,
				      struct bfddp_ctx *,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session select;
	struct bbdd_c_session change;
	bool set = false;
	uint32_t *lids;
	size_t nlids;
	char *error;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &select, &change, &lids, &nlids);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, &select, nlids);
	if (rc < 0)
		goto free_lids;

	for (size_t i = 0; i < nlids; i++) {
		struct bfddp_session bds;
		struct bfddp_session mask;
		struct bfd_session *bs;

		bs = bfd_session_lookup(lids[i]);
		if (!bs)
			continue;

		rc = bbdd_d_session_to_frr(&change, &bds, &mask, &error);
		if (rc != 0)  {
			bbdd_d_respond_interr(peer, id, error);
			free(error);
			goto free_lids;
		}

		bfddp_session_update_masked(bs, NULL, &bds, &mask);
		set = true;
	}

	if (!set) {
		/* Not sure this can actually happen. */
		bbdd_d_respond_invalid_params(peer, id,
					      "All matching sessions went away mid request");
		goto free_lids;
	}

	bbdd_d_respond_empty(peer, id);

free_lids:
	free(lids);
}

static void bbdd_d_handle_session_del(struct events_ctx *,
				      struct bfddp_ctx *,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session sess;
	bool deleted = false;
	uint32_t *lids;
	size_t nlids;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, &lids, &nlids);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, &sess, nlids);
	if (rc < 0)
		goto free_lids;

	for (size_t i = 0; i < nlids; i++) {
		struct bfd_session *bs;

		bs = bfd_session_lookup(lids[i]);
		if (bs) {
			bfddp_session_free(&bs, NULL);
			deleted = true;
		}
	}

	if (!deleted) {
		/* Not sure this can actually happen. */
		bbdd_d_respond_invalid_params(peer, id,
					      "All matching sessions went away mid request");
		goto free_lids;
	}

	bbdd_d_respond_empty(peer, id);

free_lids:
	free(lids);
}

static void bbdd_d_handle_session_show(struct events_ctx *,
				       struct bfddp_ctx *,
				       struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	struct bbdd_c_session sess;
	uint32_t *lids;
	size_t nlids;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, &lids, &nlids);
	if (rc < 0)
		return;

	return bbdd_d_handle_session_show_do(peer, id, lids, nlids);
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
		{"session-show", bbdd_d_handle_session_show},
		{"session-add", bbdd_d_handle_session_add},
		{"session-set", bbdd_d_handle_session_set},
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
