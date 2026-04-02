// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <bpf/libbpf.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <linux/if_ether.h>

#include "bbdd.h"
#include "bbdd-bpf.h"
#include "bbdd-jrpc.h"
#include "bbdd-nl.h"
#include "bbdd-prog.h"
#include "bbdd-poll.h"
#include "bbdd-sess.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"

#define BBDD_D_DEFAULT_DPLANEADDR "unix:/var/run/frr/bfdd_dplane.sock"

static void __bbdd_d_respond(struct bbdd_sock *ctl, struct json_object *obj)
{
	if (obj != NULL) {
		bbdd_jrpc_send(ctl, obj);
		json_object_put(obj);
	}
}

static void __bbdd_d_respond_invalid_params(struct bbdd_sock *ctl,
					    struct json_object *id,
					    const char *data)
{
	__bbdd_d_respond(ctl, bbdd_jrpc_new_error_inv_params(id, data));
}

static void bbdd_d_respond_invalid_params(struct bbdd_sock *ctl,
					  struct json_object *id,
					  char **data)
{
	__bbdd_d_respond_invalid_params(ctl, id, *data);
	free(*data);
	*data = NULL;
}

static void __bbdd_d_respond_interr(struct bbdd_sock *peer,
				    struct json_object *id,
				    const char *data)
{
	__bbdd_d_respond(peer, bbdd_jrpc_new_error_int_error(id, data));
}

static void bbdd_d_respond_interr(struct bbdd_sock *peer,
				  struct json_object *id,
				  char **data)
{
	__bbdd_d_respond_interr(peer, id, *data);
	free(*data);
	*data = NULL;
}

__attribute__((format(printf, 3, 4)))
static void bbdd_d_respond_interr_fmt(struct bbdd_sock *peer,
				      struct json_object *id,
				      const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (rc >= 0)
		return bbdd_d_respond_interr(peer, id, &buf);
	else
		return __bbdd_d_respond_interr(peer, id, fmt);
}

static void bbdd_d_respond_memerr(struct bbdd_sock *peer,
				  struct json_object *id)
{
	__bbdd_d_respond_interr(peer, id, "Memory allocation issue");
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

static void bbdd_d_handle_stop(struct bbdd_poll_ctx *pctx,
			       struct bbdd_sock *peer,
			       struct json_object *params_obj,
			       struct json_object *id)
{
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0)
		return bbdd_d_respond_invalid_params(peer, id, &error);

	bbdd_poll_request_quit(pctx);
	bbdd_d_respond_empty(peer, id);
}

static void bbdd_d_handle_global_stats_get(struct bbdd_bpf *bpf,
					   struct bbdd_sock *peer,
					   struct json_object *params_obj,
					   struct json_object *id)
{
	struct json_object *result;
	struct json_object *obj;
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0)
		return bbdd_d_respond_invalid_params(peer, id, &error);

	result = bbdd_bpf_global_diag_stats_json(bpf, &error);
	if (!result)
		return bbdd_d_respond_interr(peer, id, &error);

	obj = bbdd_jrpc_new_object(id);
	if (!obj)
		goto put_result;

	rc = json_object_object_add(obj, "result", result);
	if (rc != 0)
		goto put_obj;

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
put_result:
	json_object_put(result);
	bbdd_d_respond_memerr(peer, id);
}

static int bbdd_d_session_validate_interface(struct bbdd_c_session *sess,
					     struct bbdd_nl *nl,
					     char **error)
{
	struct bbdd_nl_if *ifindex_if = NULL;
	struct bbdd_nl_if *ifname_if = NULL;
	struct bbdd_nl_if *ifs;
	size_t nifs;
	int rc;

	if (!sess->ifindex_seen && !sess->ifname_seen)
		return 0;

	rc = bbdd_nl_list_ifs(nl, &ifs, &nifs, error);
	if (rc < 0)
		return -1;

	for (size_t i = 0; i < nifs; i++) {
		if (sess->ifindex_seen &&
		    ifs[i].ifindex == sess->ifindex)
			ifindex_if = &ifs[i];
		if (sess->ifname_seen &&
		    strcmp(sess->ifname, ifs[i].ifname) == 0)
			ifname_if = &ifs[i];
	}

	if (!sess->ifindex_seen)
		ifindex_if = ifname_if;
	else if (!sess->ifname_seen)
		ifname_if = ifindex_if;

	if (ifindex_if == NULL) {
		bbdd_util_fmterr(error, "No interface with ifindex %u found",
				 sess->ifindex);
		rc = -1;
		goto free_ifs;
	}
	if (ifname_if == NULL) {
		bbdd_util_fmterr(error, "No interface named `%s' found",
				 sess->ifname);
		rc = -1;
		goto free_ifs;
	}
	if (ifindex_if != ifname_if) {
		bbdd_util_fmterr(error,
				 "No interface with ifindex `%u' and name `%s' found",
				 sess->ifindex, sess->ifname);
		rc = -1;
		goto free_ifs;
	}

	if (!sess->ifindex_seen) {
		sess->ifindex_seen = 1;
		sess->ifindex = ifindex_if->ifindex;
	}
	if (!sess->ifname_seen) {
		sess->ifname_seen = 1;
		strcpy(sess->ifname, ifname_if->ifname);
	}

	rc = 0;

free_ifs:
	free(ifs);
	return rc;
}

int bbdd_d_jrpc_dissect_session_one(struct json_object *obj,
				    struct bbdd_c_session *sess,
				    char **error)
{
#define BBDD_D_SESSION_EXPAND_POL_IX(NAME, name, ...) pol_ ## name,
#define BBDD_D_SESSION_EXPAND_POLICY(NAME, name, ...) \
		[pol_ ## name] =  { .key = #name, .type = json_type_boolean },

	enum {
		BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_POL_IX)

		pol_descr,

		pol_src,
		pol_dst,

		pol_min_tx_us,
		pol_min_rx_us,
		pol_min_echo_rx,

		pol_hold_time,
		pol_ttl,
		pol_detect_mult,

		pol_ifindex,
		pol_ifname,
	};
	struct bbdd_jrpc_policy policy[] = {
		BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_POLICY)

		[pol_descr] = { .key = "descr", .type = json_type_int },

		[pol_src] = { .key = "src", .type = json_type_string },
		[pol_dst] = { .key = "dst", .type = json_type_string },

		[pol_min_tx_us] = { .key = "min_tx_us", .type = json_type_int },
		[pol_min_rx_us] = { .key = "min_rx_us", .type = json_type_int },
		[pol_min_echo_rx] = { .key = "min_echo_rx",
				      .type = json_type_int },

		[pol_hold_time] = { .key = "hold_time", .type = json_type_int },
		[pol_ttl] = { .key = "ttl", .type = json_type_int },
		[pol_detect_mult] = { .key = "detect_mult",
				      .type = json_type_int },

		[pol_ifindex] = { .key = "ifindex", .type = json_type_int },
		[pol_ifname] = { .key = "ifname", .type = json_type_string },
	};

#undef BBDD_D_SESSION_EXPAND_POLICY
#undef BBDD_D_SESSION_EXPAND_POL_IX

	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int af;
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
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

	/* Note: Caller needs to validate / recognize protocol change, here we
	 * just parse things out. */
	af = bbdd_c_session_flag_isset(sess->flags.ipv6) ? AF_INET6 : AF_INET;
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

	DISSECT_U32_NON0(descr);
	DISSECT_U32(min_tx_us);
	DISSECT_U32(min_rx_us);
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
					      bool *bulk,
					      struct bbdd_nl *nl,
					      char **error)
{
	enum {
		pol_select,
		pol_change,
		pol_bulk,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_select] = { .key = "select", .type = json_type_object },
		[pol_change] = { .key = "change", .type = json_type_object },
		[pol_bulk] =   { .key = "bulk",   .type = json_type_boolean },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	if (seen[pol_select] && select == NULL) {
		bbdd_util_fmterr(error, "RPC method doesn't allow session select");
		return -1;
	}
	if (seen[pol_change] && change == NULL) {
		bbdd_util_fmterr(error, "RPC method doesn't allow session change");
		return -1;
	}
	if (seen[pol_bulk] && bulk == NULL) {
		bbdd_util_fmterr(error, "RPC method doesn't allow bulk operations");
		return -1;
	}

	if (seen[pol_select] &&
	    (bbdd_d_jrpc_dissect_session_one(values[pol_select], select,
					     error) != 0 ||
	     ((select->ifindex_seen || select->ifname_seen) &&
	      bbdd_d_session_validate_interface(select, nl, error) != 0)))
		return -1;

	if (seen[pol_change] &&
	    (bbdd_d_jrpc_dissect_session_one(values[pol_change], change,
					     error) != 0 ||
	     ((change->ifindex_seen || change->ifname_seen) &&
	      bbdd_d_session_validate_interface(change, nl, error) < 0)))
		return -1;

	if (seen[pol_bulk])
		*bulk = json_object_get_boolean(values[pol_bulk]);
	else if (bulk != NULL)
		*bulk = false;

	return 0;
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

static void bbdd_d_session_to_c(struct bbdd_d_session *dsess,
				struct bbdd_c_session *csess)
{
	*csess = (struct bbdd_c_session){};

	for (int i = 0; i < bbdd_c_session_nflags; i++)
		/* Only mark as seen set flags. */
		csess->flags.flags[i].seen = csess->flags.flags[i].value =
			dsess->flags.flags[i];

	if ((csess->src_af = dsess->src.sa.sa_family))
		bbdd_d_sockaddr_ntop(&dsess->src.sa,
				     csess->src, sizeof(csess->src));
	if ((csess->dst_af = dsess->dst.sa.sa_family))
		bbdd_d_sockaddr_ntop(&dsess->dst.sa,
				     csess->dst, sizeof(csess->dst));

	if (dsess->ifindex != 0) {
		if_indextoname(dsess->ifindex, csess->ifname);
		csess->ifname_seen = 1;
	}

#define ASSIGN(CFIELD, DFIELD) do {		\
		csess->CFIELD = dsess->DFIELD;	\
		csess->CFIELD ## _seen = 1;	\
	} while (0)

#define ASSIGN_NON0(CFIELD, DFIELD) do {	\
		if (dsess->DFIELD)		\
			ASSIGN(CFIELD, DFIELD);	\
	} while (0)

	ASSIGN(descr, local.descr);
	ASSIGN_NON0(hold_time, hold_time);
	ASSIGN_NON0(ttl, ttl);
	ASSIGN_NON0(ifindex, ifindex);

	ASSIGN_NON0(min_tx_us, local.min_tx_us);
	ASSIGN_NON0(min_rx_us, local.min_rx_us);
	ASSIGN_NON0(min_echo_rx, local.min_echo_rx);
	ASSIGN_NON0(detect_mult, local.detect_mult);

#undef ASSIGN_NON0
#undef ASSIGN
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

static int
bbdd_d_jrpc_session_attach_state_end(struct json_object *entry_obj,
				     const struct bbdd_d_session_state_end *state)
{
	if (bbdd_d_jrpc_session_state_attach_state(entry_obj,
						   state->state) != 0 ||
	    bbdd_d_jrpc_session_state_attach_diag(entry_obj,
						  state->diag) != 0)
		return -1;
	return 0;
}

static struct json_object *
bbdd_d_jrpc_session_state_local(const struct bbdd_d_session_state_end *state)
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

	if (bbdd_d_jrpc_session_attach_state_end(entry_obj, state))
		goto put_entry_obj;

	return entry_obj;

put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

static struct json_object *
bbdd_d_jrpc_session_state_remote(const struct bbdd_d_session_data *remote)
{
	struct json_object *entry_obj;

	/* STATE_END ::= {
	 *     "state": STRING,
	 *     "diag": STRING,
	 *     "detect_mult": INT,
	 *     "min_tx_us": INT,
	 *     "min_rx_us": INT,
	 *     "min_echo_rx": INT,
	 * }
	 */

	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		return NULL;

	if (bbdd_d_jrpc_session_attach_state_end(entry_obj, &remote->state))
		goto put_entry_obj;

	if (bbdd_jrpc_append_int(entry_obj, "descr",
				 remote->descr) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "detect_mult",
				 remote->detect_mult) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_tx_us",
				 remote->min_tx_us) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_rx_us",
				 remote->min_rx_us) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_echo_rx",
				 remote->min_echo_rx) != 0)
		goto put_entry_obj;

	return entry_obj;

put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

static struct json_object *
bbdd_d_jrpc_session_state_obj(const struct bbdd_d_session *dsess)
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

	local_obj = bbdd_d_jrpc_session_state_local(&dsess->local.state);
	if (local_obj == NULL)
		goto put_entry_obj;

	remote_obj = bbdd_d_jrpc_session_state_remote(&dsess->remote);
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
					  struct bbdd_sess_dir *sdir,
					  uint32_t *descrs,
					  size_t ndescrs)
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
	 * bbdd_d_jrpc_dissect_params_session().
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
	for (size_t i = 0; i < ndescrs; i++) {
		struct bbdd_d_session *dsess;
		struct bbdd_c_session sess;

		dsess = bbdd_sess_dir_get_session(sdir, descrs[i]);
		if (dsess == NULL)
			continue;

		dumped = true;

		bbdd_d_session_to_c(dsess, &sess);

		entry_obj = json_object_new_object();
		if (entry_obj == NULL)
			goto put_array;

		state_obj = bbdd_d_jrpc_session_state_obj(dsess);
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

	if (ndescrs > 0 && !dumped) {
		/* Not sure this can actually happen. */
		__bbdd_d_respond_invalid_params(peer, id,
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

static int bbdd_d_session_apply_c(struct bbdd_d_session *dsess,
				  const struct bbdd_c_session *csess,
				  char **error)
{
	uint16_t sport;
	int err;

	for (int i = 0; i < bbdd_c_session_nflags; i++) {
		struct bbdd_c_session_flag cflag = csess->flags.flags[i];
		if (cflag.seen)
			dsess->flags.flags[i] = cflag.value;
	}

	sport = ntohs(dsess->src.sin46.port);

	if (csess->src_af) {
		err = bbdd_sock_parse_addr_af(csess->src_af, csess->src,
					      &dsess->src, error);
		if (err)
			return err;
	}
	if (csess->dst_af) {
		err = bbdd_sock_parse_addr_af(csess->dst_af, csess->dst,
					      &dsess->dst, error);
		if (err)
			return err;
	}

	/* Preserve the source port. */
	dsess->src.sin46.port = htons(sport);

	if (dsess->flags.multihop)
		dsess->dst.sin46.port = htons(BFD_MULTI_HOP_PORT);
	else
		dsess->dst.sin46.port = htons(BFD_SINGLE_HOP_PORT);

#define ASSIGN(DFIELD, CFIELD) do {					\
		if (csess->CFIELD ## _seen)				\
			dsess->DFIELD = csess->CFIELD;			\
	} while (0)

	ASSIGN(local.descr, descr);
	ASSIGN(local.detect_mult, detect_mult);
	ASSIGN(local.min_tx_us, min_tx_us);
	ASSIGN(local.min_rx_us, min_rx_us);
	ASSIGN(local.min_echo_rx, min_echo_rx);
	ASSIGN(hold_time, hold_time);
	ASSIGN(ttl, ttl);

	/* Interface is given as ifindex and ifname by the RPC, but at this
	 * point, both have been validated to match each other, and ifindex has
	 * been backfilled from ifname if not given. So we only need to care
	 * about ifindex. */
	ASSIGN(ifindex, ifindex);

#undef ASSIGN

	if (dsess->flags.shutdown) {
		dsess->local.state.state = STATE_ADMINDOWN;
		dsess->local.state.diag = DIAG_ADMIN_DOWN;
	} else {
		// xxx Need to implement state machine for proper management of
		// these states.
		dsess->local.state.state = STATE_INIT;
		dsess->local.state.diag = DIAG_NOTHING;
	}

	// xxx for now, apply for remote endpoint the same configuration as the
	// local one so that we can test packet timing before Rx is in place.
	fprintf(stderr, "xxx warning: overriding session remote configuration\n");
	dsess->remote = dsess->local;

	dsess->remote.descr = 0x45e2784b; // xxx for testing

	dsess->gen_id++;
	return 0;
}

/* Returns < 0 for errors, 0 for not a match, 1 for match. */
static int bbdd_d_session_addr_matches(int a_af, const char a[INET6_ADDRSTRLEN],
				       const struct bbdd_sockaddr *b_addr,
				       char **error)
{
	struct in6_addr a_addr = {};
	int rc;

	rc = bbdd_inet_pton(a_af, a, &a_addr, error);
	if (rc < 0)
		return rc;

	if (a_af != b_addr->sin46.family)
		return 0;

	/* Note: b_addr will have had sport / dport set, the query won't. */

	switch (a_af) {
	case AF_INET:
		return !memcmp(&a_addr, &b_addr->sin.sin_addr, 4);
	case AF_INET6:
		return !memcmp(&a_addr, &b_addr->sin6.sin6_addr,
			       sizeof(a_addr));
	}

	return 1;
}

/* Returns < 0 for errors, 0 for not a match, 1 for match. */
static int bbdd_d_session_matches(const struct bbdd_c_session *query,
				  const struct bbdd_d_session *dsess,
				  char **error)
{
	int rc;

	for (int i = 0; i < bbdd_c_session_nflags; i++)
		if (query->flags.flags[i].seen &&
		    query->flags.flags[i].value != dsess->flags.flags[i])
			return 0;

	if (query->src_af) {
		rc = bbdd_d_session_addr_matches(query->src_af, query->src,
						 &dsess->src, error);
		if (rc <= 0)
			return rc;
	}

	if (query->dst_af) {
		rc = bbdd_d_session_addr_matches(query->dst_af, query->dst,
						 &dsess->dst, error);
		if (rc <= 0)
			return rc;
	}

	/* Skip matching on ifname, which is only used to transport a
	 * human-readable netdevice name across JRPC. Instead just match
	 * on ifindex, which should be primed from ifname if necessary. */

#define FIELD(DNAME, CNAME) do {					\
		if (query->CNAME ## _seen && query->CNAME != dsess->DNAME) \
			return 0;					\
	} while (0)

	FIELD(local.descr, descr);
	FIELD(local.min_tx_us, min_tx_us);
	FIELD(local.min_rx_us, min_rx_us);
	FIELD(local.min_echo_rx, min_echo_rx);
	FIELD(hold_time, hold_time);
	FIELD(ttl, ttl);
	FIELD(local.detect_mult, detect_mult);
	FIELD(ifindex, ifindex);
#undef FIELD

	return 1;
}

static int bbdd_d_select_sessions(struct bbdd_sess_dir *sdir,
				  const struct bbdd_c_session *query,
				  uint32_t **p_descrs,
				  size_t *p_ndescrs,
				  char **error)
{
	uint32_t *descrs = NULL;
	size_t ndescrs = 0;
	size_t cap = 0;
	int rc;

	for (struct bbdd_d_session *dsess = bbdd_sess_iter_start(sdir);
	     dsess != NULL; dsess = bbdd_sess_iter_next(dsess)) {
		rc = bbdd_d_session_matches(query, dsess, error);
		if (rc < 0)
			return -1;
		if (rc == 0)
			continue;

		if (ndescrs >= cap) {
			uint32_t *new_descrs;

			cap = (cap == 0) ? 8 : cap * 2;
			new_descrs = realloc(descrs, cap * sizeof(*descrs));
			if (new_descrs == NULL)
				goto oom;
			descrs = new_descrs;
		}
		descrs[ndescrs++] = dsess->local.descr;
	}
	*p_descrs = descrs;
	*p_ndescrs = ndescrs;
	return 0;

oom:
	errno = -ENOMEM;
	bbdd_util_fmterr(error, "%m");
	free(descrs);
	return -1;
}

enum {
	bbdd_d_bits_per_long = 8 * sizeof(long),

	bbdd_d_sport_lo = 49152,
	bbdd_d_sport_hi = 65535,
	bbdd_d_sport_cap = bbdd_d_sport_hi - bbdd_d_sport_lo + 1,
	bbdd_d_sport_nwords = bbdd_d_sport_cap / bbdd_d_bits_per_long,
};

struct bbdd_d_sport_alloc {
	/* Has ones where ports are taken. */
	long occ[bbdd_d_sport_nwords];
};

static int bbdd_d_sport_get(struct bbdd_d_sport_alloc *alloc, uint16_t *port)
{
	for (int i = 0; i < bbdd_d_sport_nwords; i++) {
		int f = ffsl(~alloc->occ[i]);
		if (f) {
			f--;
			alloc->occ[i] |= 1L << f;
			*port = (uint16_t)(bbdd_d_sport_lo +
					   i * bbdd_d_bits_per_long + f);
			return 0;
		}
	}
	errno = -ENOBUFS;
	return -1;
}

static void bbdd_d_sport_put(struct bbdd_d_sport_alloc *alloc, uint16_t port)
{
	uint16_t d;
	int i, f;

	assert(port >= bbdd_d_sport_lo);
	d = port - bbdd_d_sport_lo;
	i = d / bbdd_d_bits_per_long;
	f = d % bbdd_d_bits_per_long;
	alloc->occ[i] &= ~(1L << f);
}

static int bbdd_d_session_open_sock(struct bbdd_d_session *dsess,
				    uint32_t tx_ifindex, char **error)
{
	uint16_t proto;
	union {
		struct sockaddr sa;
		struct sockaddr_ll sll;
	} sa;
	int fd;
	int rc;

	switch (dsess->dst.sa.sa_family) {
	case AF_INET:
		proto = ETH_P_IP;
		break;
	case AF_INET6:
		proto = ETH_P_IPV6;
		break;
	default:
		bbdd_util_fmterr(error, "Unsupported address family %d",
				 dsess->src.sa.sa_family);
		return -1;
	}

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(proto));
	if (fd < 0) {
		bbdd_util_fmterr(error, "socket(AF_PACKET): %m");
		return -1;
	}

	sa.sll.sll_family   = AF_PACKET;
	sa.sll.sll_protocol = htons(proto);
	sa.sll.sll_ifindex  = (int)tx_ifindex;

	rc = bind(fd, &sa.sa, sizeof(sa));
	if (rc < 0) {
		bbdd_util_fmterr(error, "bind(AF_PACKET): %m");
		goto close_fd;
	}

	dsess->sock_fd = fd;
	return 0;

close_fd:
	close(fd);
	return -1;
}

static void bbdd_d_session_close_sock(struct bbdd_d_session *dsess)
{
	close(dsess->sock_fd);
}

static uint32_t bbdd_d_cksum_acc(uint32_t sum, const void *buf, size_t len)
{
	const uint16_t *p = buf;

	while (len >= 2) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	return sum;
}

static uint16_t bbdd_d_cksum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~(uint16_t)sum;
}

static uint16_t bbdd_d_inet_cksum(const void *buf, size_t len)
{
	return bbdd_d_cksum_fold(bbdd_d_cksum_acc(0, buf, len));
}

/* udp_len is in host byte order; udp points to UDP header followed by data */
static uint16_t bbdd_d_udp6_cksum(const struct ip6_hdr *ip6,
				   const void *udp, uint16_t udp_len)
{
	struct {
		struct in6_addr src;
		struct in6_addr dst;
		__be32 len;
		uint8_t zeros[3];
		uint8_t nxt;
	} pseudo = {
		.src = ip6->ip6_src,
		.dst = ip6->ip6_dst,
		.len = htonl(udp_len),
		.nxt = IPPROTO_UDP,
	};
	uint32_t sum = 0;

	sum = bbdd_d_cksum_acc(sum, &pseudo, sizeof(pseudo));
	sum = bbdd_d_cksum_acc(sum, udp, udp_len);
	return bbdd_d_cksum_fold(sum);
}

static int bbdd_d_session_inject_pkt(const struct bbdd_d_session *dsess,
				     uint32_t tx_ifindex, char **error)
{
	enum { v1 = 1 };
	struct bfddp_control_packet bfd = {
		.version_diag = (v1 << 5) | (uint8_t) dsess->local.state.diag,
		.state_bits = (uint8_t) dsess->local.state.state << 6,
		.detection_multiplier = dsess->local.detect_mult,
		.length = sizeof(bfd),
		.local_id = htonl(dsess->local.descr),
		.remote_id = htonl(dsess->remote.descr),
		.desired_tx = htonl(dsess->local.min_tx_us),
		.required_rx = htonl(dsess->local.min_rx_us),
		.required_echo_rx = 0,
	};
	union {
		struct sockaddr    sa;
		struct sockaddr_ll sll;
	} dst_sa = {};
	ssize_t rc;

	dst_sa.sll.sll_family  = AF_PACKET;
	dst_sa.sll.sll_ifindex = (int)tx_ifindex;
	dst_sa.sll.sll_halen   = ETH_ALEN;
	memset(dst_sa.sll.sll_addr, 0xff, ETH_ALEN);

	if (dsess->dst.sa.sa_family == AF_INET) {
		struct {
			struct iphdr ip;
			struct udphdr udp;
			struct bfddp_control_packet bfd;
		} pkt = {};
		uint16_t udp_len = sizeof(pkt.udp) + sizeof(pkt.bfd);

		pkt.bfd        = bfd;
		pkt.udp.source = dsess->src.sin.sin_port;
		pkt.udp.dest   = dsess->dst.sin.sin_port;
		pkt.udp.len    = htons(udp_len);
		pkt.udp.check  = 0; /* optional for IPv4 */

		pkt.ip.version  = 4;
		pkt.ip.ihl      = 5;
		pkt.ip.tot_len  = htons(sizeof(pkt));
		pkt.ip.ttl      = dsess->ttl;
		pkt.ip.protocol = IPPROTO_UDP;
		pkt.ip.saddr    = dsess->src.sin.sin_addr.s_addr;
		pkt.ip.daddr    = dsess->dst.sin.sin_addr.s_addr;
		pkt.ip.check    = bbdd_d_inet_cksum(&pkt.ip, sizeof(pkt.ip));

		dst_sa.sll.sll_protocol = htons(ETH_P_IP);

		rc = sendto(dsess->sock_fd, &pkt, sizeof(pkt), 0,
			    &dst_sa.sa, sizeof(dst_sa.sll));
	} else {
		struct {
			struct ip6_hdr ip6;
			struct udphdr udp;
			struct bfddp_control_packet bfd;
		} pkt = {};
		uint16_t udp_len = sizeof(pkt.udp) + sizeof(pkt.bfd);

		pkt.bfd        = bfd;
		pkt.udp.source = dsess->src.sin6.sin6_port;
		pkt.udp.dest   = dsess->dst.sin6.sin6_port;
		pkt.udp.len    = htons(udp_len);

		pkt.ip6.ip6_vfc  = 0x60; /* version 6 */
		pkt.ip6.ip6_plen = htons(udp_len);
		pkt.ip6.ip6_nxt  = IPPROTO_UDP;
		pkt.ip6.ip6_hlim = dsess->ttl;
		pkt.ip6.ip6_src  = dsess->src.sin6.sin6_addr;
		pkt.ip6.ip6_dst  = dsess->dst.sin6.sin6_addr;
		pkt.udp.check    = bbdd_d_udp6_cksum(&pkt.ip6, &pkt.udp, udp_len);

		dst_sa.sll.sll_protocol = htons(ETH_P_IPV6);
		rc = sendto(dsess->sock_fd, &pkt, sizeof(pkt), 0,
			    &dst_sa.sa, sizeof(dst_sa.sll));
	}

	if (rc < 0) {
		bbdd_util_fmterr(error, "sendto(bfd_tx): %d %m", errno);
		return -1;
	}
	return 0;
}

static int bbdd_d_session_set_mark(const struct bbdd_d_session *dsess,
				   char **error)
{
	uint32_t mark = dsess->gen_id;
	int rc;

	rc = setsockopt(dsess->sock_fd, SOL_SOCKET, SO_MARK,
			&mark, sizeof(mark));
	if (rc < 0) {
		bbdd_util_fmterr(error, "setsockopt(SO_MARK): %m");
		return -1;
	}
	return 0;
}

enum { BBDD_D_NS_PER_US = 1 * 1000 };

static int
__bbdd_d_handle_session_update_bpf(struct bbdd_bpf *bpf,
				   const struct bbdd_d_session *dsess,
				   uint32_t veth_tx_ifindex,
				   bool add, char **error)
{
	uint32_t min_interval_us;
	uint32_t max_interval_us;
	uint32_t tbid = 0;    // xxx VRF support
	uint32_t flags = BPF_FIB_LOOKUP_SRC;
	uint32_t fwd_ifindex;
	int rc;

	min_interval_us = dsess->remote.min_tx_us * 75 / 100;
	if (dsess->local.detect_mult == 1)
		max_interval_us = dsess->remote.min_tx_us * 90 / 100;
	else
		max_interval_us = dsess->remote.min_tx_us;

	rc = bbdd_d_session_set_mark(dsess, error);
	if (rc != 0)
		return rc;

	if (tbid != 0)
		flags |= BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID;

	if (dsess->ifindex != 0) {
		fwd_ifindex = dsess->ifindex;
		flags |= BPF_FIB_LOOKUP_OUTPUT;
	} else {
		fwd_ifindex = veth_tx_ifindex;
	}

#define ARGS	bpf, dsess->local.descr, fwd_ifindex,			\
		&dsess->src, &dsess->dst, tbid, flags,			\
		min_interval_us, max_interval_us, dsess->gen_id,	\
		error

	if (add)
		rc = bbdd_bpf_session_add(ARGS);
	else
		rc = bbdd_bpf_session_update(ARGS);
	if (rc != 0)
		return rc;
#undef ARGS

	rc = bbdd_d_session_inject_pkt(dsess, veth_tx_ifindex, error);
	if (rc != 0)
		goto del_session;

	return 0;

	/* There's no reliable way to roll back everything, and e.g. rolling
	 * back the mark is pointless. Unless everything lines up just right,
	 * the session is broken. Even if the standard allowed to do something
	 * like add a new session with new id and then remove the old one, when
	 * the removal fails, we've got two sessions and it's broken. The only
	 * thing that we clean up is the session add. */
del_session:
	if (add)
		bbdd_bpf_session_delete(bpf, dsess->local.descr, NULL);
	return rc;
}

static int bbdd_d_handle_session_add_bpf(struct bbdd_bpf *bpf,
					 const struct bbdd_d_session *dsess,
					 uint32_t veth_tx_ifindex,
					 char **error)
{
	return __bbdd_d_handle_session_update_bpf(bpf, dsess, veth_tx_ifindex,
						  true, error);
}

static int bbdd_d_handle_session_update_bpf(struct bbdd_bpf *bpf,
					    const struct bbdd_d_session *dsess,
					    uint32_t veth_tx_ifindex,
					    char **error)
{
	return __bbdd_d_handle_session_update_bpf(bpf, dsess, veth_tx_ifindex,
						  false, error);
}

static void bbdd_d_handle_session_add(struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id,
				      struct bbdd_nl *nl,
				      struct bbdd_sess_dir *sdir,
				      struct bbdd_bpf *bpf,
				      struct bbdd_d_sport_alloc *spa,
				      uint32_t veth_tx_ifindex)
{
	struct bbdd_c_session csess;
	struct bbdd_d_session *dsess;
	uint16_t sport;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, NULL, &csess, NULL,
						nl, &error);
	if (rc != 0)
		return bbdd_d_respond_invalid_params(peer, id, &error);

	/* Note: descr is validated to be non-zero in dissection. */
	if (!csess.descr_seen) {
		csess.descr = bbdd_sess_get_unique_descr(sdir);
		csess.descr_seen = true;
	} else if (bbdd_sess_dir_has_session(sdir, csess.descr)) {
		return __bbdd_d_respond_invalid_params(peer, id, "Duplicate session");
	}

	rc = bbdd_d_sport_get(spa, &sport);
	if (rc) {
		bbdd_util_fmterr(&error, "Failed to allocate a unique source port for the new session");
		goto out;
	}

	dsess = bbdd_sess_dir_add_session(sdir, csess.descr);
	if (dsess == NULL) {
		bbdd_util_fmterr(&error, "%m");
		goto put_port;
	}

	dsess->sock_fd = -1;
	dsess->src.sin46.port = sport;

	rc = bbdd_d_session_apply_c(dsess, &csess, &error);
	if (rc != 0)
		goto sess_dir_del_session;

	rc = bbdd_d_session_open_sock(dsess, veth_tx_ifindex, &error);
	if (rc != 0)
		goto sess_dir_del_session;

	rc = bbdd_d_handle_session_add_bpf(bpf, dsess, veth_tx_ifindex, &error);
	if (rc != 0)
		goto close_sock;

	bbdd_d_respond_empty(peer, id);
	return;

close_sock:
	bbdd_d_session_close_sock(dsess);
sess_dir_del_session:
	bbdd_sess_dir_del_session(sdir, dsess);
put_port:
	bbdd_d_sport_put(spa, sport);
out:
	bbdd_d_respond_interr(peer, id, &error);
}

static int bbdd_d_parse_select_sessions(struct bbdd_sock *peer,
					struct json_object *params_obj,
					struct json_object *id,
					struct bbdd_c_session *select,
					struct bbdd_c_session *change,
					bool *bulk,
					struct bbdd_nl *nl,
					struct bbdd_sess_dir *sdir,
					uint32_t **descrs,
					size_t *ndescrs)
{
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj,
						select, change, bulk, nl, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, &error);
		return -1;
	}

	rc = bbdd_d_select_sessions(sdir, select, descrs, ndescrs, &error);
	if (rc) {
		bbdd_d_respond_interr(peer, id, &error);
		return -1;
	}

	return 0;
}

static int bbdd_d_handle_session_check_bulk(struct bbdd_sock *peer,
					    struct json_object *id,
					    bool bulk,
					    size_t ndescrs)
{
	if (ndescrs == 0) {
		__bbdd_d_respond_invalid_params(peer, id,
						"The set request matches no session");
		return -1;
	}
	if (ndescrs > 1 && !bulk) {
		__bbdd_d_respond_invalid_params(peer, id,
						"Non-bulk set request matches more than one session");
		return -1;
	}
	return 0;
}

static void bbdd_d_handle_session_set(struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id,
				      struct bbdd_nl *nl,
				      struct bbdd_sess_dir *sdir,
				      struct bbdd_bpf *bpf,
				      uint32_t tx_ifindex)
{
	struct bbdd_c_session select;
	struct bbdd_c_session change;
	bool bulk;
	bool set = false;
	uint32_t *descrs;
	size_t ndescrs;
	char *error;
	int af = 0;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &select, &change, &bulk,
					  nl, sdir,
					  &descrs, &ndescrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndescrs);
	if (rc < 0)
		goto free_descrs;

	if (change.src_af != 0)
		af = change.src_af;
	else if (change.dst_af != 0)
		af = change.dst_af;

	for (size_t i = 0; i < ndescrs; i++) {
		struct bbdd_d_session *dsess;

		dsess = bbdd_sess_dir_get_session(sdir, descrs[i]);
		if (dsess == NULL)
			continue;

		if (af != 0 && af != dsess->dst.sin46.family) {
			bbdd_util_fmterr(&error, "Session protocol change requested for id %d",
					 dsess->local.descr);
			bbdd_d_respond_invalid_params(peer, id, &error);
			goto free_descrs;
		}

		if (change.descr_seen && change.descr != dsess->local.descr) {
			bbdd_util_fmterr(&error, "Cannot change session descriptor from %d to %d",
					 dsess->local.descr, change.descr);
			bbdd_d_respond_invalid_params(peer, id, &error);
			goto free_descrs;
		}

		rc = bbdd_d_session_apply_c(dsess, &change, &error);
		if (rc != 0) {
			bbdd_d_respond_interr(peer, id, &error);
			goto free_descrs;
		}

		rc = bbdd_d_handle_session_update_bpf(bpf, dsess, tx_ifindex,
						      &error);
		if (rc != 0) {
			bbdd_d_respond_interr(peer, id, &error);
			goto free_descrs;
		}

		set = true;
	}

	if (!set) {
		/* Not sure this can actually happen. */
		__bbdd_d_respond_invalid_params(peer, id,
						"All matching sessions went away mid request");
		goto free_descrs;
	}

	bbdd_d_respond_empty(peer, id);

free_descrs:
	free(descrs);
}

static int bbdd_d_handle_session_del_one_sess(struct bbdd_sess_dir *sdir,
					      struct bbdd_d_sport_alloc *spa,
					      uint32_t descr,
					      char **error)
{
	struct bbdd_d_session *dsess;
	uint16_t sport;

	dsess = bbdd_sess_dir_get_session(sdir, descr);
	if (dsess == NULL) {
		bbdd_util_fmterr(error, "Failed to look up session %u", descr);
		return -1;
	}

	sport = dsess->src.sin46.port;
	bbdd_d_sport_put(spa, sport);

	bbdd_d_session_close_sock(dsess);
	bbdd_sess_dir_del_session(sdir, dsess);

	return 0;
}

static int bbdd_d_handle_session_del_one(struct bbdd_sess_dir *sdir,
					 struct bbdd_bpf *bpf,
					 struct bbdd_d_sport_alloc *spa,
					 uint32_t descr,
					 char **error)
{
	char *error1 = NULL;
	char *error2 = NULL;
	int rc1, rc2;

	/* Clean up as much as possible, even when one step fails. */
	rc1 = bbdd_d_handle_session_del_one_sess(sdir, spa, descr, &error1);
	rc2 = bbdd_bpf_session_delete(bpf, descr, &error2);

	if (rc1 < 0 || rc2 < 0) {
		if (error1 != NULL) {
			*error = error1;
			free(error2);
		} else {
			*error = error2;
		}

		return -1;
	}

	return 0;
}

static void
bbdd_d_handle_session_stats_do(struct bbdd_sock *peer,
			       struct json_object *id,
			       struct bbdd_bpf *bpf,
			       uint32_t *descrs,
			       size_t ndescrs,
			       struct json_object *(*cb)(struct bbdd_bpf *,
							 uint32_t, char **))
{
	struct json_object *obj;
	struct json_object *array;
	struct json_object *result_obj;
	struct json_object *entry_obj;
	struct json_object *stats_obj;
	char *error = NULL;
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
	 * Where individual SESS objects are formatted as follows:
	 *
	 * SESS ::= {
	 *     "descr": INT,
	 *     "stats": STATS,
	 * }
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

	for (size_t i = 0; i < ndescrs; i++) {
		uint32_t descr = descrs[i];

		stats_obj = cb(bpf, descr, &error);
		if (stats_obj == NULL)
			goto put_array;

		entry_obj = json_object_new_object();
		if (entry_obj == NULL)
			goto put_stats_obj;

		rc = json_object_object_add(entry_obj, "descr",
					    json_object_new_uint64(descr));
		if (rc != 0)
			goto put_entry_obj;

		rc = json_object_object_add(entry_obj, "stats", stats_obj);
		if (rc != 0)
			goto put_entry_obj;
		stats_obj = NULL;

		if (json_object_array_add(array, entry_obj) != 0)
			goto put_entry_obj;
		entry_obj = NULL;
	}

	if (json_object_object_add(result_obj, "sessions", array))
		goto put_array;
	array = NULL;

	if (json_object_object_add(obj, "result", result_obj))
		goto put_array;
	result_obj = NULL;

	bbdd_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_entry_obj:
	json_object_put(entry_obj);
put_stats_obj:
	json_object_put(stats_obj);
put_array:
	json_object_put(array);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	if (error)
		bbdd_d_respond_interr(peer, id, &error);
	else
		bbdd_d_respond_memerr(peer, id);
}

static void bbdd_d_handle_session_stats_diag(struct bbdd_sock *peer,
					     struct json_object *params_obj,
					     struct json_object *id,
					     struct bbdd_nl *nl,
					     struct bbdd_sess_dir *sdir,
					     struct bbdd_bpf *bpf)
{
	struct bbdd_c_session sess;
	uint32_t *descrs;
	size_t ndescrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &descrs, &ndescrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, bpf, descrs, ndescrs,
				       bbdd_bpf_session_diag_stats_json);
	free(descrs);
}

static void bbdd_d_handle_session_stats(struct bbdd_sock *peer,
					struct json_object *params_obj,
					struct json_object *id,
					struct bbdd_nl *nl,
					struct bbdd_sess_dir *sdir,
					struct bbdd_bpf *bpf)
{
	struct bbdd_c_session sess;
	uint32_t *descrs;
	size_t ndescrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &descrs, &ndescrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, bpf, descrs, ndescrs,
				       bbdd_bpf_session_stats_json);
	free(descrs);
}

static void bbdd_d_handle_session_del(struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id,
				      struct bbdd_nl *nl,
				      struct bbdd_sess_dir *sdir,
				      struct bbdd_bpf *bpf,
				      struct bbdd_d_sport_alloc *spa)
{
	struct bbdd_c_session sess;
	uint32_t *descrs;
	size_t ndescrs;
	bool bulk;
	int rc;
	char *last_error = NULL;
	size_t num_errors = 0;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, &bulk, nl, sdir,
					  &descrs, &ndescrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndescrs);
	if (rc < 0)
		goto free_descrs;

	for (size_t i = 0; i < ndescrs; i++) {
		char *error;

		rc = bbdd_d_handle_session_del_one(sdir, bpf, spa, descrs[i],
						   &error);
		if (rc < 0) {
			if (error != NULL) {
				free(last_error);
				last_error = error;
			}
			num_errors++;
		}
	}

	if (num_errors) {
		bbdd_d_respond_interr_fmt(peer, id,
					  "%zu/%zu sessions failed to delete. Last recorded error: `%s'",
					  num_errors, ndescrs,
					  last_error ?: "(unknown error)");
		free(last_error);
		goto free_descrs;
	}

	bbdd_d_respond_empty(peer, id);

free_descrs:
	free(descrs);
}

static void bbdd_d_handle_session_show(struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id,
				       struct bbdd_nl *nl,
				       struct bbdd_sess_dir *sdir)
{
	struct bbdd_c_session sess;
	uint32_t *descrs;
	size_t ndescrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &descrs, &ndescrs);
	if (rc < 0)
		return;

	return bbdd_d_handle_session_show_do(peer, id, sdir, descrs, ndescrs);
}

static void bbdd_d_handle_method(struct bbdd_poll_ctx *pctx,
				 struct bbdd_sess_dir *sdir,
				 struct bbdd_bpf *bpf,
				 struct bbdd_d_sport_alloc *spa,
				 uint32_t veth_tx_ifindex,
				 struct bbdd_sock *peer,
				 const char *method,
				 struct json_object *params_obj,
				 struct json_object *id,
				 struct bbdd_nl *nl)
{
	if (strcmp(method, "stop") == 0)
		bbdd_d_handle_stop(pctx, peer, params_obj, id);
	else if (strcmp(method, "ping") == 0)
		bbdd_d_handle_ping(peer, params_obj, id);
	else if (strcmp(method, "global-stats-diag") == 0)
		bbdd_d_handle_global_stats_get(bpf, peer, params_obj, id);
	else if (strcmp(method, "session-show") == 0)
		bbdd_d_handle_session_show(peer, params_obj, id, nl, sdir);
	else if (strcmp(method, "session-add") == 0)
		bbdd_d_handle_session_add(peer, params_obj, id, nl,
					  sdir, bpf, spa, veth_tx_ifindex);
	else if (strcmp(method, "session-set") == 0)
		bbdd_d_handle_session_set(peer, params_obj, id, nl,
					  sdir, bpf, veth_tx_ifindex);
	else if (strcmp(method, "session-del") == 0)
		bbdd_d_handle_session_del(peer, params_obj, id, nl,
					  sdir, bpf, spa);
	else if (strcmp(method, "session-stats-diag") == 0)
		bbdd_d_handle_session_stats_diag(peer, params_obj, id, nl,
						 sdir, bpf);
	else if (strcmp(method, "session-stats") == 0)
		bbdd_d_handle_session_stats(peer, params_obj, id, nl,
					    sdir, bpf);
	else
		__bbdd_d_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_d_ctl_activity(struct bbdd_poll_ctx *pctx,
				struct bbdd_sess_dir *sdir,
				struct bbdd_bpf *bpf,
				struct bbdd_d_sport_alloc *spa,
				uint32_t veth_tx_ifindex,
				struct bbdd_sock *ctl,
				struct bbdd_nl *nl)
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

	bbdd_d_handle_method(pctx, sdir, bpf, spa, veth_tx_ifindex,
			     &peer, method, params, id, nl);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
}

struct bbdd_context {
	struct bbdd_bpf *bpf;
	struct bbdd_sess_dir *sdir;
	struct bbdd_d_sport_alloc spa;
	struct bbdd_nl *nl;
	struct bbdd_sock ctl;
	uint32_t veth_tx_ifindex;
};

static int bbdd_d_ctl_recv(struct bbdd_poll_ctx *pctx, void *arg, char **)
{
	struct bbdd_context *bbdd = arg;

	bbdd_d_ctl_activity(pctx, bbdd->sdir, bbdd->bpf, &bbdd->spa,
			    bbdd->veth_tx_ifindex, &bbdd->ctl, bbdd->nl);
	return 0;
}

static int bbdd_d_raise_nofile(void)
{
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		fprintf(stderr, "Failed to get RLIMIT_NOFILE: %m\n");
		return -1;
	}

	rlim.rlim_cur = rlim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		fprintf(stderr, "Failed to set RLIMIT_NOFILE: %m\n");
		return -1;
	}

	/* We support bbdd_d_sport_cap sessions due to the way the source port
	 * allocator operates. To support this many sessions, we will also need
	 * to have that many extra file descriptors. */
	if (rlim.rlim_max < bbdd_d_sport_cap + 16)
		fprintf(stderr, "Warning: RLIMIT_NOFILE of %ld is too low to support the design limit of %d sessions.\n",
			rlim.rlim_max, bbdd_d_sport_cap);

	return 0;
}

static const char bbdd_d_veth_rx_name[] = "bfd_rx";
static const char bbdd_d_veth_tx_name[] = "bfd_tx";
static const uint16_t bbdd_d_veth_tx_mq_handle = 0xa000;

static int bbdd_d_num_cpus(char **error)
{
	long n;

	n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 0) {
		bbdd_util_fmterr(error, "Failed to determine number of CPUs: %m");
		return -1;
	}

	return (int) n;
}

static char *bbdd_d_cpu_mask(unsigned int i, unsigned int n, char **error)
{
	/* CPU mask words are always 32 bits. */
	unsigned int nwords = (n + 31) / 32;
	unsigned int word_idx = i / 32;
	uint32_t word_val = (uint32_t) 1 << (i % 32);
	size_t len = nwords * 9 + 1; /* 8-digit hex + comma / \0. */
	int pos = 0;
	char *buf;

	buf = malloc(len);
	if (!buf) {
		bbdd_util_fmterr(error, "%m");
		return NULL;
	}

	for (unsigned int w = nwords; w-- > 0; ) {
		uint32_t val = (w == word_idx) ? word_val : 0;

		pos += sprintf(buf + pos, "%08x,", val);
	}
	buf[--pos] = '\0';
	return buf;
}

static int bbdd_d_set_q_cpu_map(const char *path,
				unsigned int cpu, unsigned int ncpus,
				char **error)
{
	char *mask;
	ssize_t rc;
	int fd;
	int err = 0;

	mask = bbdd_d_cpu_mask(cpu, ncpus, error);
	if (!mask)
		return -1;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		bbdd_util_fmterr(error, "Failed to open `%s': %m", path);
		err = -1;
		goto free_mask;
	}

	rc = write(fd, mask, strlen(mask));
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to write to `%s': %m", path);
		err = -1;
	}

	close(fd);
free_mask:
	free(mask);
	return err;
}

#define BBDD_D_SET_Q_CPU_MAP(FMT, IFNAME, I, N, ERROR)			\
	({								\
		unsigned int BBDD_i = (I);				\
		char BBDD_path[sizeof(FMT) + IFNAMSIZ + 10];		\
									\
		sprintf(BBDD_path, FMT, (IFNAME), BBDD_i);		\
		bbdd_d_set_q_cpu_map(BBDD_path, BBDD_i, (N), (ERROR));	\
	})

static int bbdd_d_set_xps_queue(const char *ifname, unsigned int cpu,
				unsigned int ncpus, char **error)
{
	return BBDD_D_SET_Q_CPU_MAP("/sys/class/net/%s/queues/tx-%u/xps_cpus",
				    ifname, cpu, ncpus, error);
}

static int bbdd_d_set_rps_queue(const char *ifname, unsigned int cpu,
				unsigned int ncpus, char **error)
{
	return BBDD_D_SET_Q_CPU_MAP("/sys/class/net/%s/queues/rx-%u/rps_cpus",
				    ifname, cpu, ncpus, error);
}

static void bbdd_d_start_fini_veth(struct bbdd_nl *nl)
{
	char *error;
	int err;

	/* Note: the peer is autodeleted when the first endpoint is deleted. */
	err = bbdd_nl_del_if(nl, bbdd_d_veth_rx_name, &error);
	if (err) {
		fprintf(stderr, "Failed to clean up veth pair: %s\n", error);
		free(error);
	}
}

static int bbdd_d_start_init_veth_rx(struct bbdd_nl *nl,
				     struct bbdd_bpf *bpf,
				     const char *name, uint32_t ifindex,
				     unsigned int ncpus,
				     char **error)
{
	int err;

	err = bbdd_nl_set_channels(nl, ifindex, ncpus, error);
	if (err)
		return err;

	for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
		err = bbdd_d_set_rps_queue(name, cpu, ncpus, error);
		if (err)
			return err;
	}

	err = bbdd_bpf_attach_veth_rx(bpf, ifindex, error);
	if (err)
		return err;

	return bbdd_nl_set_if_up(nl, ifindex, error);
}

static int bbdd_d_start_init_veth_tx(struct bbdd_nl *nl,
				     struct bbdd_bpf *bpf,
				     const char *name, uint32_t ifindex,
				     unsigned int ncpus,
				     char **error)
{
	int err;

	err = bbdd_nl_add_qdisc(nl, ifindex, bbdd_nl_tc_h_root(),
				bbdd_d_veth_tx_mq_handle, "mq", error);
	if (err)
		return err;

	err = bbdd_nl_set_channels(nl, ifindex, ncpus, error);
	if (err)
		return err;

	err = bbdd_bpf_attach_veth_tx(bpf, ifindex, error);
	if (err)
		return err;

	for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
		uint32_t parent;

		parent = ((uint32_t) bbdd_d_veth_tx_mq_handle << 16) |
			(uint32_t)(cpu + 1);

		err = bbdd_nl_add_qdisc(nl, ifindex, parent,
					0, "fq", error);
		if (err)
			return err;

		err = bbdd_d_set_xps_queue(name, cpu, ncpus, error);
		if (err)
			return err;
	}

	return bbdd_nl_set_if_up(nl, ifindex, error);
}

static int bbdd_d_start_init_veth(struct bbdd_nl *nl,
				  struct bbdd_bpf *bpf,
				  uint32_t *tx_ifindex,
				  char **error)
{
	unsigned int ncpus;
	uint32_t rx_ifindex;
	int err;

	/* Note: this returns number of CPUs, or < 0 on failure. */
	err = bbdd_d_num_cpus(error);
	if (err < 0)
		return err;
	ncpus = (unsigned int) err;

	err = bbdd_nl_add_veth(nl,
			       bbdd_d_veth_rx_name, &rx_ifindex,
			       bbdd_d_veth_tx_name, tx_ifindex,
			       error);
	if (err)
		return err;

	err = bbdd_d_start_init_veth_rx(nl, bpf,
					bbdd_d_veth_rx_name, rx_ifindex,
					ncpus, error);
	if (err)
		goto fini_veth;

	err = bbdd_d_start_init_veth_tx(nl, bpf,
					bbdd_d_veth_tx_name, *tx_ifindex,
					ncpus, error);
	if (err)
		goto fini_veth;

	return 0;

fini_veth:
	bbdd_d_start_fini_veth(nl);
	return err;
}

struct bbdd_d_rx_socks {
#define FIELD(NAME, ...) struct bbdd_sock NAME##_sk;
	BBDD_GLOBAL_RX_SOCKETS(FIELD)
#undef FIELD
};

static void
bbdd_d_rx_sockets_close(struct bbdd_d_rx_socks *rx_socks)
{
#define CLOSE_SOCK(NAME, ...)						\
		if (rx_socks->NAME##_sk.sa.sa.sa_family != AF_UNSPEC)	\
			bbdd_sock_close_raw(&rx_socks->NAME##_sk);
	BBDD_GLOBAL_RX_SOCKETS(CLOSE_SOCK)
#undef CLOSE_SOCK
}

static int
bbdd_d_rx_sockets_open(struct bbdd_d_rx_socks *rx_socks,
		       char **error)
{
	int rc;

	*rx_socks = (struct bbdd_d_rx_socks){};

#define OPEN_SOCK(NAME, AF)						\
	do {								\
		rc = bbdd_sock_open_raw((AF), &rx_socks->NAME##_sk,	\
					error);				\
		if (rc)							\
			goto close;					\
	} while (0);

	BBDD_GLOBAL_RX_SOCKETS(OPEN_SOCK);

#undef SOCK

	return 0;

close:
	bbdd_d_rx_sockets_close(rx_socks);
	return rc;
}

static int bbdd_d_do_start(struct bbdd_sockaddr */*dplane_sa*/)
{
	struct bbdd_context bbdd = {};
	struct bbdd_poll_ctx *pctx;
	struct bbdd_d_rx_socks rx_socks;
	struct bbdd_bpf_global_config bpf_conf;
	char *error;
	int err;

	// xxx need to handle dplane_sa

	openlog("bbdd", LOG_PID | LOG_CONS, LOG_USER);

	if (bbdd_d_raise_nofile() < 0)
		goto closelog;

	bbdd.nl = bbdd_nl_create();
	if (bbdd.nl == NULL) {
		fprintf(stderr, "Failed to open netlink socket: %m\n");
		goto closelog;
	}

	pctx = bbdd_poll_init();
	if (pctx == NULL)
		goto nl_destroy;

	err = bbdd_d_rx_sockets_open(&rx_socks, &error);
	if (err) {
		bbdd_util_printerr(err, &error, "Failed to open BFD RX sockets");
		goto poll_fini;
	}

	bbdd.sdir = bbdd_sess_dir_create();
	if (bbdd.sdir == NULL) {
		fprintf(stderr, "Failed to create session directory: %m\n");
		goto rx_sockets_close;
	}

#define ASSIGN_SOCK(NAME, ...) \
		bpf_conf.NAME##_fd = rx_socks.NAME##_sk.fd;
	BBDD_GLOBAL_RX_SOCKETS(ASSIGN_SOCK);
#undef ASSIGN_SOCK

	bbdd.bpf = bbdd_bpf_create(pctx, bbdd.nl, &bpf_conf, bbdd.sdir, &error);
	if (bbdd.bpf == NULL) {
		bbdd_util_printerr(err, &error,  "Failed to initialize BPF");
		goto sess_dir_destroy;
	}

	err = bbdd_d_start_init_veth(bbdd.nl, bbdd.bpf, &bbdd.veth_tx_ifindex,
				     &error);
	if (err) {
		bbdd_util_printerr(err, &error,  "Failed to prepare veth pair");
		goto bpf_destroy;
	}

	err = bbdd_sock_open_d(&bbdd.ctl, bbdd_env.sockdir);
	if (err != 0)
		goto fini_veth;

	err = bbdd_poll_push_fd(pctx, bbdd.ctl.fd, POLLIN,
				bbdd_d_ctl_recv, &bbdd, &error);
	if (err != 0) {
		bbdd_util_printerr(err, &error, "Failed to register socket for events");
		goto sock_close_d;
	}

	err = bbdd_poll_loop(pctx, &error);
	bbdd_util_printerr(err, &error, NULL);

sock_close_d:
	bbdd_sock_close_d(&bbdd.ctl);
fini_veth:
	bbdd_d_start_fini_veth(bbdd.nl);
bpf_destroy:
	bbdd_bpf_destroy(bbdd.bpf);
sess_dir_destroy:
	bbdd_sess_dir_destroy(bbdd.sdir);
rx_sockets_close:
	bbdd_d_rx_sockets_close(&rx_socks);
poll_fini:
	bbdd_poll_fini(pctx);
nl_destroy:
	bbdd_nl_destroy(bbdd.nl);
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
	char *error;
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

	err = bbdd_sock_parse_addr_proto(dplaneaddr, &dplane_sa, &error);
	if (err) {
		bbdd_util_printerr(err, &error, NULL);
		return -1;
	}

	return bbdd_d_do_start(&dplane_sa);
}
