// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
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
					     char **error)
{
	char ifname[IFNAMSIZ] = {};
	unsigned int ifindex = 0;

	if (!sess->ifindex_seen && !sess->ifname_seen)
		return 0;

	if (sess->ifindex_seen) {
		if (!if_indextoname(sess->ifindex, ifname)) {
			bbdd_util_fmterr(error,
					 "No interface with ifindex %u found",
					 sess->ifindex);
			return -1;
		}
	}

	if (sess->ifname_seen) {
		ifindex = if_nametoindex(sess->ifname);
		if (ifindex == 0) {
			bbdd_util_fmterr(error,
					 "No interface named `%s' found",
					 sess->ifname);
			return -1;
		}
	}

	if (sess->ifindex_seen && sess->ifname_seen) {
		if (sess->ifindex != ifindex ||
		    strcmp(ifname, sess->ifname) != 0) {
			bbdd_util_fmterr(error,
					 "No interface with ifindex `%u' and name `%s' found",
					 sess->ifindex, sess->ifname);
			return -1;
		}
	}

	if (!sess->ifname_seen) {
		assert(ifname[0] != 0);
		sess->ifname_seen = 1;
		strcpy(sess->ifname, ifname);
	}

	if (!sess->ifindex_seen) {
		assert(ifindex != 0);
		sess->ifindex_seen = 1;
		sess->ifindex = ifindex;
	}

	return 0;
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

		pol_discr,

		pol_src,
		pol_dst,

		pol_min_tx_us,
		pol_min_rx_us,

		pol_hold_time,
		pol_ttl,
		pol_detect_mult,

		pol_ifindex,
		pol_ifname,
	};
	struct bbdd_jrpc_policy policy[] = {
		BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_POLICY)

		[pol_discr] = { .key = "discr", .type = json_type_int },

		[pol_src] = { .key = "src", .type = json_type_string },
		[pol_dst] = { .key = "dst", .type = json_type_string },

		[pol_min_tx_us] = { .key = "min_tx_us", .type = json_type_int },
		[pol_min_rx_us] = { .key = "min_rx_us", .type = json_type_int },

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

	DISSECT_U32_NON0(discr);
	DISSECT_U32(min_tx_us);
	DISSECT_U32(min_rx_us);
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
	      bbdd_d_session_validate_interface(select, error) != 0)))
		return -1;

	if (seen[pol_change] &&
	    (bbdd_d_jrpc_dissect_session_one(values[pol_change], change,
					     error) != 0 ||
	     ((change->ifindex_seen || change->ifname_seen) &&
	      bbdd_d_session_validate_interface(change, error) < 0)))
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

	ASSIGN(discr, local.discr);
	ASSIGN_NON0(hold_time, hold_time);
	ASSIGN_NON0(ttl, ttl);
	ASSIGN_NON0(ifindex, ifindex);

	ASSIGN_NON0(min_tx_us, local.min_tx_us);
	ASSIGN_NON0(min_rx_us, local.min_rx_us);
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
	[BBDD_BFD_PKT_STATE_ADMINDOWN] = "admindown",
	[BBDD_BFD_PKT_STATE_DOWN] = "down",
	[BBDD_BFD_PKT_STATE_INIT] = "init",
	[BBDD_BFD_PKT_STATE_UP] = "up",
};

const char *bbdd_d_bfd_state_to_str(enum bbdd_bfd_pkt_state sv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_state_str);
	const char **tab = bbdd_d_jrpc_session_state_str;

	return bbdd_d_strtab_val_to_str(sv, tab, sz);
}

int bbdd_d_bfd_state_from_str(const char *str, enum bbdd_bfd_pkt_state *sv)
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
						  enum bbdd_bfd_pkt_state sv)
{
	const char *str = bbdd_d_bfd_state_to_str(sv);

	if (str == NULL)
		return -EINVAL;
	return bbdd_jrpc_append_str(obj, "state", str);
}

static const char *bbdd_d_jrpc_session_diag_str[] = {
	[BBDD_BFD_PKT_DIAG_NOTHING] = "nothing",
	[BBDD_BFD_PKT_DIAG_TIME_EXPIRED] = "time_expired",
	[BBDD_BFD_PKT_DIAG_ECHO_FAILED] = "echo_failed",
	[BBDD_BFD_PKT_DIAG_DOWN] = "down",
	[BBDD_BFD_PKT_DIAG_FP_RESET] = "fp_reset",
	[BBDD_BFD_PKT_DIAG_PATH_DOWN] = "path_down",
	[BBDD_BFD_PKT_DIAG_CONCAT_PATH_DOWN] = "concat_path_down",
	[BBDD_BFD_PKT_DIAG_ADMIN_DOWN] = "admin_down",
	[BBDD_BFD_PKT_DIAG_REV_CONCAT_PATH_DOWN] = "rev_concat_path_down",
};

const char *bbdd_d_bfd_diag_to_str(enum bbdd_bfd_pkt_diag dv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_diag_str);
	const char **tab = bbdd_d_jrpc_session_diag_str;

	return bbdd_d_strtab_val_to_str(dv, tab, sz);
}

int bbdd_d_bfd_diag_from_str(const char *str, enum bbdd_bfd_pkt_diag *dv)
{
	size_t sz = ARRAY_SIZE(bbdd_d_jrpc_session_diag_str);
	const char **tab = bbdd_d_jrpc_session_diag_str;
	int tmp;

	if (bbdd_d_strtab_str_to_val(str, &tmp, tab, sz) < 0)
		return -EINVAL;
	*dv = tmp;
	return 0;
}

static int bbdd_d_jrpc_session_state_attach_diag(struct json_object *obj,
						 enum bbdd_bfd_pkt_diag dv)
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
	 * }
	 */

	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		return NULL;

	if (bbdd_d_jrpc_session_attach_state_end(entry_obj, &remote->state))
		goto put_entry_obj;

	if (bbdd_jrpc_append_int(entry_obj, "discr",
				 remote->discr) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "detect_mult",
				 remote->detect_mult) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_tx_us",
				 remote->min_tx_us) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_rx_us",
				 remote->min_rx_us) != 0)
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

struct json_object *bbdd_d_session_json(struct bbdd_d_session *dsess)
{
	struct json_object *entry_obj;
	struct json_object *sess_obj;
	struct json_object *state_obj;
	struct bbdd_c_session sess;
	int rc;

	bbdd_d_session_to_c(dsess, &sess);

	entry_obj = json_object_new_object();
	if (entry_obj == NULL)
		return NULL;

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

	return entry_obj;

put_sess_obj:
	json_object_put(sess_obj);
put_state_obj:
	json_object_put(state_obj);
put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

static void bbdd_d_handle_session_show_do(struct bbdd_sock *peer,
					  struct json_object *id,
					  struct bbdd_sess_dir *sdir,
					  uint32_t *discrs,
					  size_t ndiscrs)
{
	struct json_object *obj;
	struct json_object *result_obj;
	struct json_object *array;
	struct json_object *entry_obj;
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
	for (size_t i = 0; i < ndiscrs; i++) {
		struct bbdd_d_session *dsess;

		dsess = bbdd_sess_dir_get_session(sdir, discrs[i]);
		if (dsess == NULL)
			continue;

		dumped = true;

		entry_obj = bbdd_d_session_json(dsess);
		if (entry_obj == NULL)
			goto put_array;

		if (json_object_array_add(array, entry_obj) != 0)
			goto put_entry_obj;
		entry_obj = NULL;
	}

	if (ndiscrs > 0 && !dumped) {
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

	ASSIGN(local.discr, discr);
	ASSIGN(local.detect_mult, detect_mult);
	ASSIGN(local.min_tx_us, min_tx_us);
	ASSIGN(local.min_rx_us, min_rx_us);
	ASSIGN(hold_time, hold_time);
	ASSIGN(ttl, ttl);

	/* Interface is given as ifindex and ifname by the RPC, but at this
	 * point, both have been validated to match each other, and ifindex has
	 * been backfilled from ifname if not given. So we only need to care
	 * about ifindex. */
	ASSIGN(ifindex, ifindex);

#undef ASSIGN

	/* A session marked as `shutdown' needs to be made admin down. On
	 * contrary, an admin down session that is not `shutdown' anymore can be
	 * set to INIT again. Otherwise don't touch the state. */
	if (dsess->flags.shutdown) {
		dsess->local.state.state = BBDD_BFD_PKT_STATE_ADMINDOWN;
		dsess->local.state.diag = BBDD_BFD_PKT_DIAG_ADMIN_DOWN;
	} else if (dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN) {
		dsess->local.state.state = BBDD_BFD_PKT_STATE_INIT;
		dsess->local.state.diag = BBDD_BFD_PKT_DIAG_NOTHING;
	}

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

	FIELD(local.discr, discr);
	FIELD(local.min_tx_us, min_tx_us);
	FIELD(local.min_rx_us, min_rx_us);
	FIELD(hold_time, hold_time);
	FIELD(ttl, ttl);
	FIELD(local.detect_mult, detect_mult);
	FIELD(ifindex, ifindex);
#undef FIELD

	return 1;
}

static int bbdd_d_select_sessions(struct bbdd_sess_dir *sdir,
				  const struct bbdd_c_session *query,
				  uint32_t **p_discrs,
				  size_t *p_ndiscrs,
				  char **error)
{
	uint32_t *discrs = NULL;
	size_t ndiscrs = 0;
	size_t cap = 0;
	int rc;

	for (struct bbdd_d_session *dsess = bbdd_sess_iter_start(sdir);
	     dsess != NULL; dsess = bbdd_sess_iter_next(dsess)) {
		rc = bbdd_d_session_matches(query, dsess, error);
		if (rc < 0)
			return -1;
		if (rc == 0)
			continue;

		if (ndiscrs >= cap) {
			uint32_t *new_discrs;

			cap = (cap == 0) ? 8 : cap * 2;
			new_discrs = realloc(discrs, cap * sizeof(*discrs));
			if (new_discrs == NULL)
				goto oom;
			discrs = new_discrs;
		}
		discrs[ndiscrs++] = dsess->local.discr;
	}
	*p_discrs = discrs;
	*p_ndiscrs = ndiscrs;
	return 0;

oom:
	errno = -ENOMEM;
	bbdd_util_fmterr(error, "%m");
	free(discrs);
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

static void bbdd_d_handle_session_add(struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id,
				      struct bbdd_nl *nl,
				      struct bbdd_sess_dir *sdir,
				      struct bbdd_bpf *bpf,
				      struct bbdd_d_sport_alloc *spa)
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

	/* Note: discr is validated to be non-zero in dissection. */
	if (!csess.discr_seen) {
		csess.discr = bbdd_sess_get_unique_discr(sdir);
		csess.discr_seen = true;
	} else if (bbdd_sess_dir_has_session(sdir, csess.discr)) {
		return __bbdd_d_respond_invalid_params(peer, id, "Duplicate session");
	}

	rc = bbdd_d_sport_get(spa, &sport);
	if (rc) {
		bbdd_util_fmterr(&error, "Failed to allocate a unique source port for the new session");
		goto out;
	}

	dsess = bbdd_sess_dir_add_session(sdir, csess.discr);
	if (dsess == NULL) {
		bbdd_util_fmterr(&error, "%m");
		goto put_port;
	}

	dsess->src.sin46.port = sport;

	dsess->local.state.state = BBDD_BFD_PKT_STATE_INIT;
	dsess->local.state.diag = BBDD_BFD_PKT_DIAG_NOTHING;

	dsess->remote.discr = 0;
	dsess->remote.detect_mult = 1;
	dsess->remote.state.state = BBDD_BFD_PKT_STATE_DOWN;
	dsess->remote.state.diag = BBDD_BFD_PKT_DIAG_NOTHING;
	dsess->remote.min_rx_us = bbdd_prog_slow_interval_us;
	dsess->remote.min_tx_us = bbdd_prog_slow_interval_us;

	rc = bbdd_d_session_apply_c(dsess, &csess, &error);
	if (rc != 0)
		goto sess_dir_del_session;

	rc = bbdd_bpf_session_add(bpf, dsess, &error);
	if (rc != 0)
		goto sess_dir_del_session;

	bbdd_d_respond_empty(peer, id);
	return;

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
					uint32_t **discrs,
					size_t *ndiscrs)
{
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj,
						select, change, bulk, nl, &error);
	if (rc != 0) {
		bbdd_d_respond_invalid_params(peer, id, &error);
		return -1;
	}

	rc = bbdd_d_select_sessions(sdir, select, discrs, ndiscrs, &error);
	if (rc) {
		bbdd_d_respond_interr(peer, id, &error);
		return -1;
	}

	return 0;
}

static int bbdd_d_handle_session_check_bulk(struct bbdd_sock *peer,
					    struct json_object *id,
					    bool bulk,
					    size_t ndiscrs)
{
	if (ndiscrs == 0) {
		__bbdd_d_respond_invalid_params(peer, id,
						"The set request matches no session");
		return -1;
	}
	if (ndiscrs > 1 && !bulk) {
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
				      struct bbdd_bpf *bpf)
{
	struct bbdd_c_session select;
	struct bbdd_c_session change;
	bool bulk;
	bool set = false;
	uint32_t *discrs;
	size_t ndiscrs;
	char *error;
	int af = 0;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &select, &change, &bulk,
					  nl, sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndiscrs);
	if (rc < 0)
		goto free_discrs;

	if (change.src_af != 0)
		af = change.src_af;
	else if (change.dst_af != 0)
		af = change.dst_af;

	for (size_t i = 0; i < ndiscrs; i++) {
		struct bbdd_d_session *dsess;

		dsess = bbdd_sess_dir_get_session(sdir, discrs[i]);
		if (dsess == NULL)
			continue;

		if (af != 0 && af != dsess->dst.sin46.family) {
			bbdd_util_fmterr(&error, "Session protocol change requested for id %d",
					 dsess->local.discr);
			bbdd_d_respond_invalid_params(peer, id, &error);
			goto free_discrs;
		}

		if (change.discr_seen && change.discr != dsess->local.discr) {
			bbdd_util_fmterr(&error, "Cannot change session discriminator from %d to %d",
					 dsess->local.discr, change.discr);
			bbdd_d_respond_invalid_params(peer, id, &error);
			goto free_discrs;
		}

		rc = bbdd_d_session_apply_c(dsess, &change, &error);
		if (rc != 0) {
			bbdd_d_respond_interr(peer, id, &error);
			goto free_discrs;
		}

		rc = bbdd_bpf_session_update(bpf, dsess, &error);
		if (rc != 0) {
			bbdd_d_respond_interr(peer, id, &error);
			goto free_discrs;
		}

		set = true;
	}

	if (!set) {
		/* Not sure this can actually happen. */
		__bbdd_d_respond_invalid_params(peer, id,
						"All matching sessions went away mid request");
		goto free_discrs;
	}

	bbdd_d_respond_empty(peer, id);

free_discrs:
	free(discrs);
}

static int bbdd_d_handle_session_del_one(struct bbdd_sess_dir *sdir,
					 struct bbdd_bpf *bpf,
					 struct bbdd_d_sport_alloc *spa,
					 uint32_t discr,
					 char **error)
{
	struct bbdd_d_session *dsess;
	uint16_t sport;

	dsess = bbdd_sess_dir_get_session(sdir, discr);
	if (dsess == NULL) {
		bbdd_util_fmterr(error, "Failed to look up session %u", discr);
		return -1;
	}

	bbdd_bpf_session_del(bpf, dsess);

	sport = dsess->src.sin46.port;
	bbdd_d_sport_put(spa, sport);

	bbdd_sess_dir_del_session(sdir, dsess);

	return 0;
}

static void
bbdd_d_handle_session_stats_do(struct bbdd_sock *peer,
			       struct json_object *id,
			       struct bbdd_bpf *bpf,
			       uint32_t *discrs,
			       size_t ndiscrs,
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
	 *     "discr": INT,
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

	for (size_t i = 0; i < ndiscrs; i++) {
		uint32_t discr = discrs[i];

		stats_obj = cb(bpf, discr, &error);
		if (stats_obj == NULL)
			goto put_array;

		entry_obj = json_object_new_object();
		if (entry_obj == NULL)
			goto put_stats_obj;

		rc = json_object_object_add(entry_obj, "discr",
					    json_object_new_uint64(discr));
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
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, bpf, discrs, ndiscrs,
				       bbdd_bpf_session_diag_stats_json);
	free(discrs);
}

static void bbdd_d_handle_session_stats(struct bbdd_sock *peer,
					struct json_object *params_obj,
					struct json_object *id,
					struct bbdd_nl *nl,
					struct bbdd_sess_dir *sdir,
					struct bbdd_bpf *bpf)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, bpf, discrs, ndiscrs,
				       bbdd_bpf_session_stats_json);
	free(discrs);
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
	uint32_t *discrs;
	size_t ndiscrs;
	bool bulk;
	int rc;
	char *last_error = NULL;
	size_t num_errors = 0;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, &bulk, nl, sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndiscrs);
	if (rc < 0)
		goto free_discrs;

	for (size_t i = 0; i < ndiscrs; i++) {
		char *error;

		rc = bbdd_d_handle_session_del_one(sdir, bpf, spa, discrs[i],
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
					  num_errors, ndiscrs,
					  last_error ?: "(unknown error)");
		free(last_error);
		goto free_discrs;
	}

	bbdd_d_respond_empty(peer, id);

free_discrs:
	free(discrs);
}

static void bbdd_d_handle_session_show(struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id,
				       struct bbdd_nl *nl,
				       struct bbdd_sess_dir *sdir)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, nl, sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	return bbdd_d_handle_session_show_do(peer, id, sdir, discrs, ndiscrs);
}

static void bbdd_d_handle_bfdd_connect(struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	enum {
		pol_proto,
		pol_addr,
		pol_port,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_proto] = { .key = "proto", .type = json_type_string,
				.required = true },
		[pol_addr]  = { .key = "addr",  .type = json_type_string,
				.required = true },
		[pol_port]  = { .key = "port",  .type = json_type_string,
				.required = false },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	const char *proto;
	const char *addr;
	const char *port;
	char *error = NULL;
	int af;
	int rc;

	rc = bbdd_jrpc_dissect(params_obj, policy, seen, values,
			       ARRAY_SIZE(policy), &error);
	if (rc != 0)
		return bbdd_d_respond_invalid_params(peer, id, &error);

	proto = json_object_get_string(values[pol_proto]);
	addr = json_object_get_string(values[pol_addr]);
	port = json_object_get_string(values[pol_port]);

	af = bbdd_sock_name_to_af(proto, &error);
	if (af < 0)
		return bbdd_d_respond_invalid_params(peer, id, &error);

	if (af != AF_UNIX)
		return __bbdd_d_respond_invalid_params(peer, id, "Only `unix' protocol supported");

	fprintf(stderr, "bfdd-connect: proto=%s addr=%s port=%s\n",
		proto, addr, port ?: "(none)");

	bbdd_d_respond_empty(peer, id);
}

static void bbdd_d_handle_method(struct bbdd_poll_ctx *pctx,
				 struct bbdd_sess_dir *sdir,
				 struct bbdd_bpf *bpf,
				 struct bbdd_d_sport_alloc *spa,
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
					  sdir, bpf, spa);
	else if (strcmp(method, "session-set") == 0)
		bbdd_d_handle_session_set(peer, params_obj, id, nl, sdir, bpf);
	else if (strcmp(method, "session-del") == 0)
		bbdd_d_handle_session_del(peer, params_obj, id, nl,
					  sdir, bpf, spa);
	else if (strcmp(method, "session-stats-diag") == 0)
		bbdd_d_handle_session_stats_diag(peer, params_obj, id, nl,
						 sdir, bpf);
	else if (strcmp(method, "session-stats") == 0)
		bbdd_d_handle_session_stats(peer, params_obj, id, nl,
					    sdir, bpf);
	else if (strcmp(method, "bfdd-connect") == 0)
		bbdd_d_handle_bfdd_connect(peer, params_obj, id);
	else
		__bbdd_d_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_d_ctl_activity(struct bbdd_poll_ctx *pctx,
				struct bbdd_sess_dir *sdir,
				struct bbdd_bpf *bpf,
				struct bbdd_d_sport_alloc *spa,
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

	bbdd_d_handle_method(pctx, sdir, bpf, spa,
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
};

static int bbdd_d_ctl_recv(struct bbdd_poll_ctx *pctx, void *arg, char **)
{
	struct bbdd_context *bbdd = arg;

	bbdd_d_ctl_activity(pctx, bbdd->sdir, bbdd->bpf, &bbdd->spa,
			    &bbdd->ctl, bbdd->nl);
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
	 * to have that many extra file discriminators. */
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
				     const char *name, uint32_t ifindex,
				     unsigned int ncpus,
				     char **error)
{
	int err;

	for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
		err = bbdd_d_set_rps_queue(name, cpu, ncpus, error);
		if (err)
			return err;
	}

	return bbdd_nl_set_if_up(nl, ifindex, error);
}

static int bbdd_d_start_init_veth_tx(struct bbdd_nl *nl,
				     const char *name, uint32_t ifindex,
				     unsigned int ncpus,
				     char **error)
{
	int err;

	err = bbdd_nl_add_qdisc(nl, ifindex, bbdd_nl_tc_h_root(),
				bbdd_d_veth_tx_mq_handle, "mq", error);
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
				  uint32_t *rx_ifindex,
				  uint32_t *tx_ifindex,
				  char **error)
{
	unsigned int ncpus;
	int err;

	/* Note: this returns number of CPUs, or < 0 on failure. */
	err = bbdd_d_num_cpus(error);
	if (err < 0)
		return err;
	ncpus = (unsigned int) err;

	err = bbdd_nl_add_veth(nl,
			       bbdd_d_veth_rx_name, rx_ifindex,
			       bbdd_d_veth_tx_name, tx_ifindex,
			       ncpus, error);
	if (err)
		return err;

	err = bbdd_d_start_init_veth_rx(nl, bbdd_d_veth_rx_name, *rx_ifindex,
					ncpus, error);
	if (err)
		goto fini_veth;

	err = bbdd_d_start_init_veth_tx(nl, bbdd_d_veth_tx_name, *tx_ifindex,
					ncpus, error);
	if (err)
		goto fini_veth;

	return 0;

fini_veth:
	bbdd_d_start_fini_veth(nl);
	return err;
}

static int
bbdd_d_sock_open_udp(struct bbdd_sock *sock, uint16_t af, uint16_t port,
		     char **error)
{
	struct bbdd_sockaddr addr;

	addr.sa.sa_family = af;
	switch (af) {
	case AF_INET:
		addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin.sin_port = htons(port);
		addr.len = sizeof(addr.sin);
		break;
	case AF_INET6:
		addr.sin6.sin6_addr = in6addr_any;
		addr.sin6.sin6_port = htons(port);
		addr.len = sizeof(addr.sin6);
		break;
	}

	return bbdd_sock_open_udp(addr, sock, error);
}

static int bbdd_d_sig_cb(struct bbdd_poll_ctx *pctx, void *data,
			 char **/*error*/)
{
	struct signalfd_siginfo info;
	sigset_t mask;
	int fd = *(int *) data;

	read(fd, &info, sizeof(info));

	/* Graceful shutdown on first signal. Restore the default disposition
	 * and unblock so that a subsequent signal (e.g. a repeated Ctrl-C)
	 * terminates the process immediately. */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	bbdd_poll_request_quit(pctx);
	return 0;
}

static int bbdd_d_do_start(void)
{
	struct bbdd_context bbdd = {};
	struct bbdd_poll_ctx *pctx;
	struct bbdd_sock ipv4_shop_sk;
	struct bbdd_sock ipv6_shop_sk;
	struct bbdd_sock ipv4_mhop_sk;
	struct bbdd_sock ipv6_mhop_sk;
	uint32_t veth_rx_ifindex;
	uint32_t veth_tx_ifindex;
	struct bbdd_bpf_global_config bpf_conf;
	sigset_t sig_mask;
	char *error;
	int sig_fd;
	int err;

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

	err = bbdd_d_sock_open_udp(&ipv4_shop_sk, AF_INET,
				   BFD_SINGLE_HOP_PORT, &error);
	if (err != 0)
		goto poll_fini;

	err = bbdd_d_sock_open_udp(&ipv6_shop_sk, AF_INET6,
				   BFD_SINGLE_HOP_PORT, &error);
	if (err != 0)
		goto ipv4_shop_close;

	err = bbdd_d_sock_open_udp(&ipv4_mhop_sk, AF_INET,
				   BFD_MULTI_HOP_PORT, &error);
	if (err != 0)
		goto ipv6_shop_close;

	err = bbdd_d_sock_open_udp(&ipv6_mhop_sk, AF_INET6,
				   BFD_MULTI_HOP_PORT, &error);
	if (err != 0)
		goto ipv4_mhop_close;

	bbdd.sdir = bbdd_sess_dir_create();
	if (bbdd.sdir == NULL) {
		fprintf(stderr, "Failed to create session directory: %m\n");
		goto ipv6_mhop_close;
	}

	err = bbdd_d_start_init_veth(bbdd.nl,
				     &veth_rx_ifindex,
				     &veth_tx_ifindex,
				     &error);
	if (err) {
		bbdd_util_printerr(err, &error,  "Failed to prepare veth pair");
		goto sess_dir_destroy;
	}

	bpf_conf = (struct bbdd_bpf_global_config) {
		.ipv4_shop_fd = ipv4_shop_sk.fd,
		.ipv6_shop_fd = ipv6_shop_sk.fd,
		.ipv4_mhop_fd = ipv4_mhop_sk.fd,
		.ipv6_mhop_fd = ipv6_mhop_sk.fd,
		.veth_rx_ifindex = veth_rx_ifindex,
		.veth_tx_ifindex = veth_tx_ifindex,
	};

	bbdd.bpf = bbdd_bpf_create(pctx, bbdd.nl, &bpf_conf, bbdd.sdir, &error);
	if (bbdd.bpf == NULL) {
		bbdd_util_printerr(err, &error,  "Failed to initialize BPF");
		goto fini_veth;
	}

	err = bbdd_sock_open_d(&bbdd.ctl, bbdd_env.sockdir);
	if (err != 0)
		goto bpf_destroy;

	err = bbdd_poll_push_fd(pctx, bbdd.ctl.fd, POLLIN,
				bbdd_d_ctl_recv, &bbdd, &error);
	if (err != 0) {
		bbdd_util_printerr(err, &error, "Failed to register socket for events");
		goto sock_close_d;
	}

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGINT);
	sigaddset(&sig_mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &sig_mask, NULL);

	sig_fd = signalfd(-1, &sig_mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sig_fd < 0) {
		fprintf(stderr, "Failed to create signalfd: %m\n");
		goto sock_close_d;
	}

	err = bbdd_poll_push_fd(pctx, sig_fd, POLLIN,
				bbdd_d_sig_cb, &sig_fd, &error);
	if (err != 0) {
		bbdd_util_printerr(err, &error, "Failed to register signal fd");
		goto sig_fd_close;
	}

	err = bbdd_poll_loop(pctx, &error);
	bbdd_util_printerr(err, &error, NULL);

sig_fd_close:
	close(sig_fd);
sock_close_d:
	bbdd_sock_close_d(&bbdd.ctl);
bpf_destroy:
	bbdd_bpf_destroy(bbdd.bpf);
fini_veth:
	bbdd_d_start_fini_veth(bbdd.nl);
sess_dir_destroy:
	bbdd_sess_dir_destroy(bbdd.sdir);
ipv6_mhop_close:
	bbdd_sock_close_udp(&ipv6_mhop_sk);
ipv4_mhop_close:
	bbdd_sock_close_udp(&ipv4_mhop_sk);
ipv6_shop_close:
	bbdd_sock_close_udp(&ipv6_shop_sk);
ipv4_shop_close:
	bbdd_sock_close_udp(&ipv4_shop_sk);
poll_fini:
	bbdd_poll_fini(pctx);
nl_destroy:
	bbdd_nl_destroy(bbdd.nl);
closelog:
	closelog();
	return err;
}

int bbdd_d_start(int argc, char **argv)
{
	if (argc > 0 && strcmp(*argv, "help") == 0) {
		fprintf(stderr, "Usage: bbdd start\n");
		return 0;
	}

	if (argc > 0) {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	return bbdd_d_do_start();
}
