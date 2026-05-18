// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-d.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/resource.h>
#include <sys/timerfd.h>

#include <bpf/libbpf.h>
#include <json-c/json_object.h>
#include <json-c/json_util.h>
#include <linux/if_ether.h>

#include "bbdd.h"
#include "bbdd-bfdd.h"
#include "bbdd-c.h"
#include "bbdd-bpf.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-prog.h"
#include "bbdd-sess.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"
#include "bfddp_packet.h"

enum {
	bbdd_d_bits_per_long = 8 * sizeof(long),

	bbdd_d_sport_lo = 49152,
	bbdd_d_sport_hi = 65535,
	bbdd_d_sport_cap = bbdd_d_sport_hi - bbdd_d_sport_lo + 1,
	bbdd_d_sport_nwords = bbdd_d_sport_cap / bbdd_d_bits_per_long,
};

struct bbdd_d_sport_alloc {
	/* Has 1-bits where ports are taken, 0-bits where they are free. */
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

struct bbdd_d {
	struct bbdd_poll_ctx *pctx;
	struct bbdd_bfdd *bfdd;
	struct bbdd_bpf *bpf;
	struct bbdd_mon *mon;
	struct bbdd_nl *nl;
	struct bbdd_sess_dir *sdir;
	struct bbdd_d_sport_alloc spa;
	struct bbdd_sock ctl;
	struct bbdd_d_global_diag_stats diag_stats;
};

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

	bbdd_util_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	bbdd_util_jrpc_respond_memerr(peer, id);
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
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	bbdd_poll_request_quit(pctx);
	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_d_stat_fmterr(char **error)
{
	bbdd_util_fmterr(error, "Failed to format stats to JSON: %m");
}

static int bbdd_d_add_stat(struct json_object *obj,
			   const char *name, uint64_t value,
			   char **error)
{
	int rc;
	rc = bbdd_jrpc_append_uint64(obj, name, value);
	if (rc)
		bbdd_d_stat_fmterr(error);
	return rc;
}

static int bbdd_d_global_diag_stats_json(struct bbdd_d *d,
					 struct json_object *obj,
					 char **error)
{
	struct bbdd_d_global_diag_stats *stats = &d->diag_stats;

#define FIELD(NAME) {							\
		uint64_t value = stats->NAME;				\
		if (bbdd_d_add_stat(obj, #NAME, value, error))		\
			return -1;					\
	}

	BBDD_D_GLOBAL_DIAG_STATS(FIELD)
#undef FIELD

	return 0;
}

static void bbdd_d_handle_global_stats_get(struct bbdd_d *d,
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
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	result = bbdd_bpf_global_diag_stats_json(d->bpf, &error);
	if (!result)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	rc = bbdd_d_global_diag_stats_json(d, result, &error);
	if (rc != 0)
		goto put_result;

	obj = bbdd_jrpc_new_object(id);
	if (!obj)
		goto put_result;

	rc = json_object_object_add(obj, "result", result);
	if (rc != 0)
		goto put_obj;

	bbdd_util_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
put_result:
	json_object_put(result);
	bbdd_util_jrpc_respond_memerr(peer, id);
}

static int bbdd_d_session_validate_netif(struct bbdd_c_session_netif *netif,
					 char **error)
{
	char ifname[IFNAMSIZ] = {};
	unsigned int ifindex = 0;

	if (!netif->ifindex_seen && !netif->name_seen)
		return 0;

	if (netif->ifindex_seen) {
		if (!if_indextoname(netif->ifindex, ifname)) {
			bbdd_util_fmterr(error,
					 "No interface with ifindex %u found",
					 netif->ifindex);
			return -1;
		}
	}

	if (netif->name_seen) {
		if (netif->name[0] != '\0') {
			ifindex = if_nametoindex(netif->name);
			if (ifindex == 0) {
				bbdd_util_fmterr(error,
						 "No interface named `%s' found",
						 netif->name);
				return -1;
			}
		} else {
			ifindex = 0;
		}
	}

	if (netif->ifindex_seen && netif->name_seen) {
		if (netif->name[0] == '\0') {
			bbdd_util_fmterr(error,
					 "Interface ifindex `%u' given together with request to unset interface",
					 netif->ifindex);
			return -1;
		}
		if (netif->ifindex != ifindex ||
		    strcmp(ifname, netif->name) != 0) {
			bbdd_util_fmterr(error,
					 "No interface with ifindex `%u' and name `%s' found",
					 netif->ifindex, netif->name);
			return -1;
		}
	}

	if (!netif->name_seen) {
		assert(ifname[0] != 0);
		netif->name_seen = 1;
		strcpy(netif->name, ifname);
	}

	if (!netif->ifindex_seen) {
		netif->ifindex_seen = 1;
		netif->ifindex = ifindex;
	}

	return 0;
}

static int bbdd_d_session_validate_vrf(struct bbdd_c_session_vrf *sess_vrf,
				       struct bbdd_nl *nl,
				       char **error)
{
	uint32_t table;
	int err;

	err = bbdd_d_session_validate_netif(&sess_vrf->netif, error);
	if (err != 0)
		return err;

	/* We can't backfill VRF name / ifindex given routing table. */
	if (!sess_vrf->netif.ifindex_seen)
		return 0;

	/* But we can a) backfill table from VRF, and b) when both are given,
	 * cross-validate. */

	err = bbdd_nl_get_vrf_table(nl, sess_vrf->netif.ifindex, &table, error);
	if (err != 0)
		return err;

	if (!sess_vrf->table_seen) {
		sess_vrf->table = table;
		sess_vrf->table_seen = 1;
	} else if (sess_vrf->table != table) {
		bbdd_util_fmterr(error, "VRF x table mismatch: VRF `%s' has table %d, but %d given",
				 sess_vrf->netif.name, table,
				 sess_vrf->table);
		return -1;
	}

	return 0;
}

static int bbdd_d_jrpc_dissect_netif_name(struct bbdd_c_session_netif *netif,
					  struct json_object *name,
					  char **error)
{
	if (name == NULL) {
		netif->unset = true;
	} else {
		int rc;

		rc = bbdd_jrpc_strcpy(name, netif->name, sizeof(netif->name),
				      error);
		if (rc < 0)
			return rc;

		netif->name_seen = 1;
	}
	return 0;
}

static int bbdd_d_jrpc_dissect_addr_obj(struct bbdd_c_session_addr *addr,
					struct json_object *obj,
					char **error)
{
	enum {
		pol_addr,
		pol_family,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_addr] =   { .key = "addr",   .type = json_type_string,
				 .required = true },
		[pol_family] = { .key = "family", .type = json_type_string,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	const char *family_str;
	int rc;

	rc = bbdd_jrpc_dissect(obj, policy, seen, values, ARRAY_SIZE(policy),
			       error);
	if (rc != 0)
		return rc;

	assert(values[pol_addr] != NULL);
	assert(values[pol_family] != NULL);

	family_str = json_object_get_string(values[pol_family]);
	if (strcmp(family_str, "ipv4") == 0)
		addr->af = AF_INET;
	else if (strcmp(family_str, "ipv6") == 0)
		addr->af = AF_INET6;
	else {
		bbdd_util_fmterr(error, "Unknown address family `%s'",
				 family_str);
		return -1;
	}

	return bbdd_jrpc_strcpy(values[pol_addr],
				addr->str, sizeof(addr->str), error);
}

static int bbdd_d_jrpc_dissect_addr(struct bbdd_c_session_addr *addr,
				    struct json_object *value,
				    char **error)
{
	if (value == NULL) {
		addr->unset = true;
		return 0;
	}

	return bbdd_d_jrpc_dissect_addr_obj(addr, value, error);
}

int bbdd_d_jrpc_dissect_session_one(struct json_object *obj,
				    struct bbdd_c_session *sess,
				    char **error)
{
#define BBDD_D_SESSION_EXPAND_POL_IX(NAME, name, ...) pol_ ## name,
#define BBDD_D_SESSION_EXPAND_POLICY(NAME, name, ...) \
		[pol_ ## name] =  { .key = #name, .type = json_type_boolean },

	enum {
		BBDD_SESS_FLAGS(BBDD_D_SESSION_EXPAND_POL_IX)

		pol_discr,

		pol_src,
		pol_dst,

		pol_min_tx_us,
		pol_min_rx_us,

		pol_hold_time_us,
		pol_ttl,
		pol_detect_mult,

		pol_netif_name,
		pol_netif_index,
		pol_vrf_name,
		pol_vrf_index,
		pol_vrf_table,
	};
	struct bbdd_jrpc_policy policy[] = {
		BBDD_SESS_FLAGS(BBDD_D_SESSION_EXPAND_POLICY)

		[pol_discr] = { .key = "discr", .type = json_type_int },

		[pol_dst] = { .key = "dst", .type = json_type_object },
		[pol_src] = { .key = "src", .type = json_type_object,
			      .nullable = true },

		[pol_min_tx_us] = { .key = "min_tx_us", .type = json_type_int },
		[pol_min_rx_us] = { .key = "min_rx_us", .type = json_type_int },

		[pol_hold_time_us] = { .key = "hold_time_us",
				       .type = json_type_int },
		[pol_ttl] = { .key = "ttl", .type = json_type_int },
		[pol_detect_mult] = { .key = "detect_mult",
				      .type = json_type_int },

		[pol_netif_name]  = { .key = "netif_name",
				      .type = json_type_string,
				      .nullable = true, },
		[pol_netif_index] = { .key = "netif_index",
				      .type = json_type_int },
		[pol_vrf_name]    = { .key = "vrf_name",
				      .type = json_type_string,
				      .nullable = true, },
		[pol_vrf_index]   = { .key = "vrf_index",
				      .type = json_type_int },
		[pol_vrf_table]   = { .key = "vrf_table",
				      .type = json_type_int },
	};

#undef BBDD_D_SESSION_EXPAND_POLICY
#undef BBDD_D_SESSION_EXPAND_POL_IX

	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
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

	BBDD_SESS_FLAGS(BBDD_D_SESSION_EXPAND_DISSECT);

#undef BBDD_D_SESSION_EXPAND_DISSECT

	/* Note: Caller needs to validate / recognize protocol change, here we
	 * just parse things out. */
	if (seen[pol_src] &&
	    bbdd_d_jrpc_dissect_addr(&sess->src, values[pol_src], error))
		goto fail;

	if (seen[pol_dst] &&
	    bbdd_d_jrpc_dissect_addr(&sess->dst, values[pol_dst], error))
		goto fail;

	if (seen[pol_netif_name] &&
	    bbdd_d_jrpc_dissect_netif_name(&sess->netif,
					   values[pol_netif_name], error) < 0)
		goto fail;

	if (seen[pol_vrf_name] &&
	    bbdd_d_jrpc_dissect_netif_name(&sess->vrf.netif,
					   values[pol_vrf_name], error) < 0)
		goto fail;

	if (seen[pol_vrf_table]) {
		if (bbdd_jrpc_get_uint32(values[pol_vrf_table],
					 &sess->vrf.table, error) < 0)
			goto fail;
		sess->vrf.table_seen = 1;
	}

#define DISSECT(POLNAME, NAME, CB) do {					\
		if (seen[pol_ ## POLNAME]) {				\
			if (CB(values[pol_ ## POLNAME], &sess->NAME,	\
			       error) < 0)				\
				goto fail;				\
			sess->NAME ## _seen = 1;			\
		}							\
	} while (0)

#define DISSECT_U32(NAME) DISSECT(NAME, NAME, bbdd_jrpc_get_uint32)
#define DISSECT_U8(NAME) DISSECT(NAME, NAME, bbdd_jrpc_get_uint8)

	DISSECT(discr, discr, bbdd_jrpc_get_uint32_non0);
	DISSECT_U32(min_tx_us);
	DISSECT_U32(min_rx_us);
	DISSECT_U32(hold_time_us);
	DISSECT_U8(ttl);
	DISSECT_U8(detect_mult);
	DISSECT(netif_index, netif.ifindex, bbdd_jrpc_get_uint32_non0);
	DISSECT(vrf_index, vrf.netif.ifindex, bbdd_jrpc_get_uint32_non0);

#undef DISSECT_U8
#undef DISSECT_U32
#undef DISSECT

	return 0;

fail:
	return -1;
}

int bbdd_d_jrpc_dissect_validate_session(struct json_object *obj,
					 struct bbdd_c_session *sess,
					 const char *what,
					 struct bbdd_nl *nl,
					 char **error)
{
	int rc;

	if (obj == NULL) {
		bbdd_util_fmterr(error, "RPC method doesn't allow session %s",
				 what);
		return -1;
	}

	rc = bbdd_d_jrpc_dissect_session_one(obj, sess, error);
	if (rc != 0)
		return rc;

	if (sess->netif.ifindex_seen || sess->netif.name_seen) {
		rc = bbdd_d_session_validate_netif(&sess->netif, error);
		if (rc != 0)
			return rc;
	}

	if (sess->vrf.netif.name_seen) {
		rc = bbdd_d_session_validate_vrf(&sess->vrf, nl, error);
		if (rc != 0)
			return rc;
	}

	return 0;
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

	if (seen[pol_select]) {
		rc = bbdd_d_jrpc_dissect_validate_session(values[pol_select],
							  select, "select",
							  nl, error);
		if (rc != 0)
			return rc;
	}

	if (seen[pol_change]) {
		rc = bbdd_d_jrpc_dissect_validate_session(values[pol_change],
							  change, "change",
							  nl, error);
		if (rc != 0)
			return rc;
	}

	if (seen[pol_bulk]) {
		if (bulk == NULL) {
			bbdd_util_fmterr(error, "RPC method doesn't allow bulk operations");
			return -1;
		}

		*bulk = json_object_get_boolean(values[pol_bulk]);
	} else if (bulk != NULL) {
		*bulk = false;
	}

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

static void bbdd_d_session_to_c_vrf(struct bbdd_d_session *dsess,
				    struct bbdd_c_session_vrf *sess_vrf)
{
	if (dsess->vrf_ifindex != 0) {
		if_indextoname(dsess->vrf_ifindex, sess_vrf->netif.name);
		sess_vrf->netif.name_seen = 1;
		sess_vrf->netif.ifindex = dsess->vrf_ifindex;
		sess_vrf->netif.ifindex_seen = 1;
	} else {
		sess_vrf->netif.unset = true;
	}

	if (dsess->vrf_table != 0) {
		sess_vrf->table = dsess->vrf_table;
		sess_vrf->table_seen = 1;
	}
}

static void bbdd_d_session_to_c_addr(struct bbdd_c_session_addr *to,
				     struct bbdd_sockaddr *from)
{
	to->af = from->sa.sa_family;
	if (to->af != 0)
		bbdd_d_sockaddr_ntop(&from->sa, to->str, sizeof(to->str));
	else
		to->unset = true;
}

static void bbdd_d_session_to_c(struct bbdd_d_session *dsess,
				struct bbdd_c_session *csess)
{
	*csess = (struct bbdd_c_session){};

	for (int i = 0; i < bbdd_sess_nflags; i++)
		/* Only mark as seen set flags. */
		csess->flags.flags[i].seen = csess->flags.flags[i].value =
			dsess->flags.flags[i];

	bbdd_d_session_to_c_addr(&csess->src, &dsess->src);
	bbdd_d_session_to_c_addr(&csess->dst, &dsess->dst);

	if (dsess->ifindex != 0) {
		if_indextoname(dsess->ifindex, csess->netif.name);
		csess->netif.name_seen = 1;
	} else {
		csess->netif.unset = true;
	}

	bbdd_d_session_to_c_vrf(dsess, &csess->vrf);

#define ASSIGN(CFIELD, DFIELD) do {		\
		csess->CFIELD = dsess->DFIELD;	\
		csess->CFIELD ## _seen = 1;	\
	} while (0)

#define ASSIGN_NON0(CFIELD, DFIELD) do {	\
		if (dsess->DFIELD)		\
			ASSIGN(CFIELD, DFIELD);	\
	} while (0)

	ASSIGN(discr, local.discr);
	ASSIGN_NON0(hold_time_us, hold_time_us);
	ASSIGN_NON0(ttl, ttl);
	ASSIGN_NON0(netif.ifindex, ifindex);

	ASSIGN_NON0(min_tx_us, local.timing.min_tx_us);
	ASSIGN_NON0(min_rx_us, local.timing.min_rx_us);
	ASSIGN_NON0(detect_mult, local.timing.detect_mult);

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
				 remote->timing.detect_mult) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_tx_us",
				 remote->timing.min_tx_us) != 0 ||
	    bbdd_jrpc_append_int(entry_obj, "min_rx_us",
				 remote->timing.min_rx_us) != 0)
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

	if (bbdd_jrpc_append_obj(entry_obj, "remote", &remote_obj) ||
	    bbdd_jrpc_append_obj(entry_obj, "local", &local_obj))
		goto put_remote_obj;

	return entry_obj;

put_remote_obj:
	json_object_put(remote_obj);
put_local_obj:
	json_object_put(local_obj);
put_entry_obj:
	json_object_put(entry_obj);
	return NULL;
}

struct json_object *bbdd_d_session_json(struct bbdd_bpf *bpf,
					struct bbdd_d_session *dsess,
					char **error)
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

	rc = bbdd_bpf_session_state_json(bpf, dsess->local.discr, state_obj,
					 error);
	if (rc != 0)
		goto put_state_obj;

	sess_obj = bbdd_c_jrpc_session_obj(&sess);
	if (sess_obj == NULL)
		goto put_state_obj;

	if (bbdd_jrpc_append_obj(entry_obj, "data", &sess_obj) ||
	    bbdd_jrpc_append_obj(entry_obj, "state", &state_obj))
		goto put_sess_obj;

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
					  struct bbdd_bpf *bpf,
					  uint32_t *discrs,
					  size_t ndiscrs)
{
	struct json_object *obj;
	struct json_object *result_obj;
	struct json_object *array;
	struct json_object *entry_obj;
	char *error = NULL;
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

		entry_obj = bbdd_d_session_json(bpf, dsess, &error);
		if (entry_obj == NULL)
			goto put_array;

		if (json_object_array_add(array, entry_obj) != 0)
			goto put_entry_obj;
		entry_obj = NULL;
	}

	if (ndiscrs > 0 && !dumped) {
		/* Not sure this can actually happen. */
		bbdd_util_jrpc_respond_inv_params(peer, id, "All matching sessions went away mid request");
		goto put_array;
	}

	rc = json_object_object_add(result_obj, "sessions", array);
	if (rc != 0)
		goto put_array;

	if (json_object_object_add(obj, "result", result_obj))
		goto put_result_obj;

	bbdd_util_jrpc_send(peer, obj);
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
	if (error != NULL)
		bbdd_util_jrpc_respond_interr_err(peer, id, &error);
	else
		bbdd_util_jrpc_respond_memerr(peer, id);
}

static void bbdd_d_session_state_changed(struct bbdd_d_session *dsess,
					 struct bbdd_bpf *bpf,
					 struct bbdd_mon *mon,
					 struct bbdd_bfdd *bfdd)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_session;
	struct json_object *sess_obj;
	struct json_object *params;
	struct json_object *msg;
	char *error = NULL;
	int rc = -1;

	if (bfdd != NULL) {
		if (bbdd_bfdd_send_state_change(bfdd, dsess, &error) != 0)
			bbdd_mon_senderr(mon, &error,
					 "session %u: failed to send state change to bfdd",
					 dsess->local.discr);
	}

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	msg = bbdd_jrpc_new_notif("session:change");
	if (msg == NULL)
		return;

	params = json_object_new_object();
	if (params == NULL)
		goto put_msg;

	sess_obj = bbdd_d_session_json(bpf, dsess, &error);
	if (sess_obj != NULL) {
		if (bbdd_jrpc_append_obj(params, "session", &sess_obj)) {
			json_object_put(sess_obj);
			goto no_session;
		}
	} else {
no_session:
		if (bbdd_jrpc_append_int(params, "discr", dsess->local.discr))
			goto put_params;
	}

	if (bbdd_jrpc_append_obj(msg, "params", &params))
		goto put_params;

	bbdd_mon_send(mon, msg, topic);
	rc = 0;

put_params:
	json_object_put(params);
put_msg:
	json_object_put(msg);

	if (rc != 0)
		bbdd_mon_senderr(mon, &error, "session %u: failed to format notification",
				 dsess->local.discr);
}

static void bbdd_d_session_state_changed_cb(struct bbdd_d_session *dsess,
					    void *data)
{
	struct bbdd_d *d = data;

	bbdd_d_session_state_changed(dsess, d->bpf, d->mon, d->bfdd);
}

/* Return number of found sessions, or < 0 on error. The last matched session,
 * if any, is returned through ret_discr. */
static int bbdd_d_match_session(struct bbdd_d_session **ret_dsess,
				struct bbdd_sess_dir *sdir,
				const struct bbdd_bpf_match_digest *digest,
				char **error)
{
	int nmatch = 0;
	int err;

	for (struct bbdd_d_session *dsess = bbdd_sess_iter_start(sdir);
	     dsess != NULL; dsess = bbdd_sess_iter_next(dsess)) {
		const struct bbdd_sockaddr *ss_src = &dsess->src;
		const struct bbdd_sockaddr *ss_dst = &dsess->dst;

		if (digest->multihop != dsess->flags.multihop)
			continue;

		if (dsess->ifindex != 0 && dsess->ifindex != digest->ifindex)
			continue;

		if (dsess->vrf_table != digest->table)
			continue;

		if (digest->ttl < dsess->ttl)
			continue;

		/* This is incoming packet aimed at us, so we need to match
		 * packet DST vs. session SRC and vice versa. */

		if (ss_src->sa.sa_family == 0)
			/* Session doesn't have set source address. */
			goto src;
		if (ss_src->sa.sa_family != digest->dst.sa.sa_family)
			continue;

		err = bbdd_sockaddr_eq(ss_src, &digest->dst, error);
		if (err < 0)
			return err;
		if (err == false)
			/* ss_src != pk_dst. */
			continue;

	src:
		if (ss_dst->sa.sa_family == 0)
			/* Session doesn't have set destination address. Weird,
			 * but we are not validating here, so eat it. */
			goto match;
		if (ss_dst->sa.sa_family != digest->src.sa.sa_family)
			continue;

		err = bbdd_sockaddr_eq(ss_dst, &digest->src, error);
		if (err < 0)
			return err;
		if (err == false)
			/* ss_dst != pk_src. */
			continue;

	match:
		nmatch++;
		*ret_dsess = dsess;
	}

	return nmatch;
}

static int bbdd_d_match_session_cb(struct bbdd_d_session **ret_dsess,
				   struct bbdd_bpf_match_digest *digest,
				   void *data, char **error)
{
	struct bbdd_d *d = data;

	return bbdd_d_match_session(ret_dsess, d->sdir, digest, error);
}

static struct bbdd_d_session *
bbdd_d_find_session_cb(uint32_t discr, void *data)
{
	struct bbdd_d *d = data;

	return bbdd_sess_dir_get_session(d->sdir, discr);
}

static void __bbdd_d_session_apply_c(struct bbdd_d_session *dsess,
				     const struct bbdd_c_session *csess,
				     bool set_src, struct bbdd_sockaddr *src,
				     bool set_dst, struct bbdd_sockaddr *dst)
{
	uint16_t sport;

	for (int i = 0; i < bbdd_sess_nflags; i++) {
		struct bbdd_flag cflag = csess->flags.flags[i];
		if (cflag.seen)
			dsess->flags.flags[i] = cflag.value;
	}

	sport = ntohs(dsess->src.sin46.port);

	if (set_src)
		dsess->src = *src;
	if (set_dst)
		dsess->dst = *dst;

	/* Preserve the source port. */
	dsess->src.sin46.port = htons(sport);

	if (dsess->flags.multihop)
		dsess->dst.sin46.port = htons(BFD_MULTI_HOP_PORT);
	else
		dsess->dst.sin46.port = htons(BFD_SINGLE_HOP_PORT);

	/* Interface is given as netif_index,netif_name / vrf_index,vrf_name by
	 * the RPC, but at this point, the indices have been validated to match
	 * names, and cross-backfilled. So we only care about ifindex. */

	if (csess->netif.unset)
		dsess->ifindex = 0;
	else if (csess->netif.ifindex_seen)
		dsess->ifindex = csess->netif.ifindex;

	if (csess->vrf.netif.unset) {
		/* Unset both VRF and table. If the user wants to override the
		 * table in the same request, do it with boring fields. */
		dsess->vrf_ifindex = 0;
		dsess->vrf_table = 0;
	} else if (csess->vrf.netif.ifindex_seen) {
		dsess->vrf_ifindex = csess->vrf.netif.ifindex;
	}

	/* Boring fields. */

#define ASSIGN(DFIELD, CFIELD) do {					\
		if (csess->CFIELD ## _seen)				\
			dsess->DFIELD = csess->CFIELD;			\
	} while (0)

	ASSIGN(local.discr, discr);
	ASSIGN(local.timing.detect_mult, detect_mult);
	ASSIGN(local.timing.min_tx_us, min_tx_us);
	ASSIGN(local.timing.min_rx_us, min_rx_us);
	ASSIGN(hold_time_us, hold_time_us);
	ASSIGN(ttl, ttl);
	ASSIGN(vrf_table, vrf.table);

#undef ASSIGN

	if (dsess->flags.shutdown) {
		/* RFC: 6.18.6: [Unless enabling session] Set bfd.SessionState
		 * to AdminDown */
		dsess->local.state.state = BBDD_BFD_PKT_STATE_ADMINDOWN;
		dsess->local.state.diag = BBDD_BFD_PKT_DIAG_ADMIN_DOWN;
	} else if (dsess->local.state.state == BBDD_BFD_PKT_STATE_ADMINDOWN) {
		/* RFC: 6.18.6: If enabling session Set bfd.SessionState to
		 * Down */
		dsess->local.state.state = BBDD_BFD_PKT_STATE_DOWN;
		dsess->local.state.diag = BBDD_BFD_PKT_DIAG_DOWN;
	}
}

static int bbdd_d_session_apply_c_addr(bool *set, struct bbdd_sockaddr *to,
				       const struct bbdd_c_session_addr *from,
				       char **error)
{
	if (from->unset) {
		*set = true;
		to->sa.sa_family = 0;
		return 0;

	} else if (from->af != 0) {
		*set = true;
		return bbdd_sock_parse_addrstr(from->af, from->str, to, error);

	} else {
		*set = false;
		return 0;
	}
}

int bbdd_d_session_apply_c(struct bbdd_d_session *dsess,
			   const struct bbdd_c_session *csess,
			   struct bbdd_nl *nl,
			   bool *changed, char **error)
{
	struct bbdd_sockaddr src = {};  bool set_src;
	struct bbdd_sockaddr dst = {};  bool set_dst;
	struct bbdd_d_session orig_dsess = *dsess;
	int err;

	/* Some things cannot be validated during parsing, but only when we see
	 * the actual data. Validate them here. */

	if (csess->discr_seen && dsess->local.discr != 0 &&
	    csess->discr != dsess->local.discr) {
		bbdd_util_fmterr(error, "Session discriminator change is not allowed");
		return -1;
	}

	/* Validate that src and dst will end up with the same address family.
	 * Determine what each will be after applying the change. */
	{
		int new_dst_af;
		int new_src_af;

		assert(!csess->dst.unset);
		if (csess->dst.af != 0)
			new_dst_af = csess->dst.af;
		else
			new_dst_af = dsess->dst.sin46.family;

		if (new_dst_af == 0) {
			bbdd_util_fmterr(error, "No destination address");
			return -1;
		}

		if (csess->src.unset)
			new_src_af = 0;
		else if (csess->src.af != 0)
			new_src_af = csess->src.af;
		else
			new_src_af = dsess->src.sin46.family;

		if (new_src_af != 0 && new_src_af != new_dst_af) {
			bbdd_util_fmterr(error, "%s destination but %s source address",
					 bbdd_sock_af_to_str(new_dst_af),
					 bbdd_sock_af_to_str(new_src_af));
			return -1;
		}
	}

	/* Parse the addresses.*/
	err = bbdd_d_session_apply_c_addr(&set_src, &src, &csess->src, error) ?:
	      bbdd_d_session_apply_c_addr(&set_dst, &dst, &csess->dst, error);
	if (err)
		return err;

	/* To validate VRF, construct a VRF configuration view from the current
	 * dsess, with the csess changes applied on top, and check that. */
	{
		struct bbdd_c_session_vrf sess_vrf = {};

		bbdd_d_session_to_c_vrf(dsess, &sess_vrf);
		if (csess->vrf.netif.unset) {
			sess_vrf.netif.name_seen = 0;
			sess_vrf.netif.ifindex_seen = 0;
		}
		if (csess->vrf.netif.name_seen) {
			memcpy(sess_vrf.netif.name, csess->vrf.netif.name,
			       sizeof(sess_vrf.netif.name));
			sess_vrf.netif.name_seen = 1;
		}
		if (csess->vrf.netif.ifindex_seen) {
			sess_vrf.netif.ifindex = csess->vrf.netif.ifindex;
			sess_vrf.netif.ifindex_seen = 1;
		}
		if (csess->vrf.table_seen) {
			sess_vrf.table = csess->vrf.table;
			sess_vrf.table_seen = 1;
		}

		err = bbdd_d_session_validate_vrf(&sess_vrf, nl, error);
		if (err != 0)
			return err;
	}

	/* Some values shouldn't be zero. */

#define MANDATORY_NON0(NAME, NS) do {					\
		if ((!csess->NAME ## _seen && dsess->NS NAME == 0) ||	\
		    (csess->NAME ## _seen && csess->NAME == 0))	{	\
			bbdd_util_fmterr(error, #NAME " needs to be non-0"); \
			return -1;					\
		}							\
	} while (0)

	MANDATORY_NON0(discr, local.);
	MANDATORY_NON0(min_rx_us, local.timing.);
	MANDATORY_NON0(min_tx_us, local.timing.);
	MANDATORY_NON0(detect_mult, local.timing.);

#undef MANDATORY_NON0

	/* Now that we've validated everything, apply it infallibly. */
	__bbdd_d_session_apply_c(dsess, csess,
				 set_src, &src,
				 set_dst, &dst);
	if (changed != NULL)
		*changed = memcmp(&orig_dsess, dsess, sizeof(*dsess)) != 0;
	return 0;
}

/* Returns < 0 for errors, 0 for not a match, 1 for match. */
static int bbdd_d_session_addr_matches(const struct bbdd_c_session_addr *query,
				       const struct bbdd_sockaddr *b_addr,
				       char **error)
{
	struct in6_addr a_addr = {};
	int rc;

	if (query->af == 0)
		return 1;

	rc = bbdd_inet_pton(query->af, query->str, &a_addr, error);
	if (rc < 0)
		return rc;

	if (query->af != b_addr->sin46.family)
		return 0;

	/* Note: b_addr will have had sport / dport set, the query won't. */

	switch (query->af) {
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

	for (int i = 0; i < bbdd_sess_nflags; i++)
		if (query->flags.flags[i].seen &&
		    query->flags.flags[i].value != dsess->flags.flags[i])
			return 0;

	rc = bbdd_d_session_addr_matches(&query->src, &dsess->src, error);
	if (rc <= 0)
		return rc;

	rc = bbdd_d_session_addr_matches(&query->dst, &dsess->dst, error);
	if (rc <= 0)
		return rc;

	/* When matching on netif, we just consider unset and ifindex. At this
	 * point, the name and index are known to match each other and have been
	 * cross-filled when one was missing. */

	if (query->netif.unset && dsess->ifindex != 0)
		return 0;
	if (query->vrf.netif.unset && dsess->vrf_ifindex != 0)
		return 0;

#define FIELD(DNAME, CNAME) do {					\
		if (query->CNAME ## _seen && query->CNAME != dsess->DNAME) \
			return 0;					\
	} while (0)

	FIELD(local.discr, discr);
	FIELD(local.timing.detect_mult, detect_mult);
	FIELD(local.timing.min_tx_us, min_tx_us);
	FIELD(local.timing.min_rx_us, min_rx_us);
	FIELD(hold_time_us, hold_time_us);
	FIELD(ttl, ttl);
	FIELD(ifindex, netif.ifindex);
	FIELD(vrf_ifindex, vrf.netif.ifindex);
	FIELD(vrf_table, vrf.table);
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

struct bbdd_d_hold {
	struct bbdd_d_session *dsess;
	struct bbdd_poll_ctx *pctx;
	struct bbdd_bpf *bpf;
	struct bbdd_mon *mon;
	struct bbdd_bfdd **bfdd;
	int timer_fd;
};

static void bbdd_d_hold_destroy(struct bbdd_d_hold *hold)
{
	bbdd_poll_unset_fd(hold->pctx, hold->timer_fd);
	close(hold->timer_fd);
	free(hold);
}

static int bbdd_d_hold_timer_cb(struct bbdd_poll_ctx *pctx, short,
				void *data, char **)
{
	struct bbdd_d_hold *hold = data;
	struct bbdd_d_session *dsess = hold->dsess;
	uint64_t expirations;
	char *error;
	int rc;

	/* Drain the timerfd so poll does not fire again. */
	(void) read(hold->timer_fd, &expirations, sizeof(expirations));

	rc = bbdd_bpf_session_activate(hold->bpf, dsess, &error);
	if (rc != 0) {
		bbdd_mon_senderr(hold->mon, &error, "session %u: failed to activate",
				 dsess->local.discr);
		goto out;
	}

	/* Don't report hold time anymore now that it expired. */
	dsess->hold_time_us = 0;
	bbdd_d_session_state_changed(dsess, hold->bpf, hold->mon, *hold->bfdd);

out:
	bbdd_d_hold_destroy(hold);
	dsess->hold = NULL;
	return 0;
}

static struct bbdd_d_hold *
bbdd_d_hold_create(struct bbdd_d *d, struct bbdd_d_session *dsess, char **error)
{
	struct itimerspec ts = {
		.it_value = {
			.tv_sec  = dsess->hold_time_us / 1000000,
			.tv_nsec = (dsess->hold_time_us % 1000000) * 1000,
		},
	};
	struct bbdd_d_hold *hold;
	int timer_fd;
	int rc;

	*error = NULL;

	hold = malloc(sizeof(*hold));
	if (hold == NULL)
		goto err;

	/* Bump by 1 ns to avoid hold_time_us of 0 meaning timer disarm. */
	ts.it_value.tv_nsec++;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timer_fd < 0)
		goto free_hold;

	rc = timerfd_settime(timer_fd, 0, &ts, NULL);
	if (rc < 0)
		goto close_timer_fd;

	rc = bbdd_poll_set_fd(d->pctx, timer_fd, POLLIN,
			      bbdd_d_hold_timer_cb, hold, error);
	if (rc != 0)
		goto close_timer_fd;

	*hold = (struct bbdd_d_hold) {
		.dsess = dsess,
		.pctx = d->pctx,
		.bpf = d->bpf,
		.mon = d->mon,
		.bfdd = &d->bfdd,
		.timer_fd = timer_fd,
	};
	return hold;

close_timer_fd:
	close(timer_fd);
free_hold:
	free(hold);
err:
	if (*error == NULL)
		bbdd_util_fmterr(error, "%m");
	return NULL;
}

static int bbdd_d_session_add(struct bbdd_d *d,
			      const struct bbdd_c_session *csess, char **error)
{
	struct bbdd_d_session *dsess;
	uint16_t sport;
	int rc;

	rc = bbdd_d_sport_get(&d->spa, &sport);
	if (rc) {
		bbdd_util_fmterr(error, "Failed to allocate a unique source port for the new session");
		return -1;
	}

	dsess = bbdd_sess_dir_add_session(d->sdir, csess->discr);
	if (dsess == NULL) {
		bbdd_util_fmterr(error, "%m");
		goto put_port;
	}

	dsess->src.sin46.port = htons(sport);

	/* RFC 6.2: Down state means that the session is down (or has just been
	 * created). */
	dsess->local.state.state = BBDD_BFD_PKT_STATE_DOWN;
	dsess->local.state.diag = BBDD_BFD_PKT_DIAG_DOWN;
	/* Arbitrary defaults. */
	dsess->local.timing.detect_mult = 1;
	dsess->local.timing.min_rx_us = bbdd_prog_slow_interval_us;
	dsess->local.timing.min_tx_us = bbdd_prog_slow_interval_us;

	dsess->remote.discr = 0;
	dsess->remote.state.state = BBDD_BFD_PKT_STATE_DOWN;
	dsess->remote.state.diag = BBDD_BFD_PKT_DIAG_NOTHING;
	dsess->remote.timing = dsess->local.timing;

	rc = bbdd_d_session_apply_c(dsess, csess, d->nl, NULL, error);
	if (rc != 0)
		goto sess_dir_del_session;

	rc = bbdd_bpf_session_add(d->bpf, dsess, error);
	if (rc != 0)
		goto sess_dir_del_session;

	dsess->hold = bbdd_d_hold_create(d, dsess, error);
	if (dsess->hold == NULL)
		goto sess_bpf_session_del;

	return 0;

sess_bpf_session_del:
	bbdd_bpf_session_del(d->bpf, dsess);
sess_dir_del_session:
	bbdd_sess_dir_del_session(d->sdir, dsess);
put_port:
	bbdd_d_sport_put(&d->spa, sport);
	return -1;
}

static void bbdd_d_handle_session_add(struct bbdd_d *d,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session csess;
	char *error;
	int rc;

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, NULL, &csess, NULL,
						d->nl, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	/* Note: discr is validated to be non-zero in dissection. */
	if (!csess.discr_seen) {
		csess.discr = bbdd_sess_get_unique_discr(d->sdir);
		csess.discr_seen = true;
	} else if (bbdd_sess_dir_has_session(d->sdir, csess.discr)) {
		return bbdd_util_jrpc_respond_inv_params(peer, id, "Duplicate session");
	}

	rc = bbdd_d_session_add(d, &csess, &error);
	if (rc < 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	bbdd_util_jrpc_respond_empty(peer, id);
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

	rc = bbdd_d_jrpc_dissect_params_session(params_obj, select,
						change, bulk, nl, &error);
	if (rc != 0) {
		bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);
		return -1;
	}

	rc = bbdd_d_select_sessions(sdir, select, discrs, ndiscrs, &error);
	if (rc) {
		bbdd_util_jrpc_respond_interr_err(peer, id, &error);
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
		bbdd_util_jrpc_respond_inv_params(peer, id, "The set request matches no session");
		return -1;
	}
	if (ndiscrs > 1 && !bulk) {
		bbdd_util_jrpc_respond_inv_params(peer, id, "Non-bulk set request matches more than one session");
		return -1;
	}
	return 0;
}

static void bbdd_d_handle_session_set(struct bbdd_d *d,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session select;
	struct bbdd_c_session change;
	bool bulk;
	bool set = false;
	uint32_t *discrs;
	size_t ndiscrs;
	char *error;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &select, &change, &bulk,
					  d->nl, d->sdir, &discrs, &ndiscrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndiscrs);
	if (rc < 0)
		goto free_discrs;

	for (size_t i = 0; i < ndiscrs; i++) {
		struct bbdd_d_session *dsess;
		bool changed;

		dsess = bbdd_sess_dir_get_session(d->sdir, discrs[i]);
		if (dsess == NULL)
			continue;

		rc = bbdd_d_session_apply_c(dsess, &change, d->nl, &changed,
					    &error);
		if (rc != 0) {
			bbdd_util_wraperr(&error, "Session %u: %s",
					  dsess->local.discr, error);
			bbdd_util_jrpc_respond_interr_err(peer, id, &error);
			goto free_discrs;
		}

		set = true;

		if (dsess->hold != NULL)
			continue;

		rc = bbdd_bpf_session_update(d->bpf, dsess, &error);
		if (rc != 0) {
			bbdd_util_jrpc_respond_interr_err(peer, id, &error);
			goto free_discrs;
		}

		if (changed)
			bbdd_d_session_state_changed(dsess, d->bpf, d->mon, d->bfdd);
	}

	if (!set) {
		/* Not sure this can actually happen. */
		bbdd_util_jrpc_respond_inv_params(peer, id, "All matching sessions went away mid request");
		goto free_discrs;
	}

	bbdd_util_jrpc_respond_empty(peer, id);

free_discrs:
	free(discrs);
}

static int bbdd_d_handle_session_del_one(struct bbdd_d *d, uint32_t discr,
					 char **error)
{
	struct bbdd_d_session *dsess;
	uint16_t sport;

	dsess = bbdd_sess_dir_get_session(d->sdir, discr);
	if (dsess == NULL) {
		bbdd_util_fmterr(error, "Failed to look up session %u", discr);
		return -1;
	}

	if (dsess->hold != NULL)
		bbdd_d_hold_destroy(dsess->hold);

	bbdd_bpf_session_del(d->bpf, dsess);

	sport = ntohs(dsess->src.sin46.port);
	bbdd_d_sport_put(&d->spa, sport);

	bbdd_sess_dir_del_session(d->sdir, dsess);

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

		if (bbdd_jrpc_append_uint64(entry_obj, "discr", discr) ||
		    bbdd_jrpc_append_obj(entry_obj, "stats", &stats_obj))
			goto put_entry_obj;

		if (json_object_array_add(array, entry_obj) != 0)
			goto put_entry_obj;
		entry_obj = NULL;
	}

	if (bbdd_jrpc_append_obj(result_obj, "sessions", &array) ||
	    bbdd_jrpc_append_obj(obj, "result", &result_obj))
		goto put_array;

	bbdd_util_jrpc_send(peer, obj);
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
		bbdd_util_jrpc_respond_interr_err(peer, id, &error);
	else
		bbdd_util_jrpc_respond_memerr(peer, id);
}

static void bbdd_d_handle_session_stats_diag(struct bbdd_d *d,
					     struct bbdd_sock *peer,
					     struct json_object *params_obj,
					     struct json_object *id)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, d->nl, d->sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, d->bpf, discrs, ndiscrs,
				       bbdd_bpf_session_diag_stats_json);
	free(discrs);
}

static void bbdd_d_handle_session_stats(struct bbdd_d *d,
					struct bbdd_sock *peer,
					struct json_object *params_obj,
					struct json_object *id)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, d->nl, d->sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	bbdd_d_handle_session_stats_do(peer, id, d->bpf, discrs, ndiscrs,
				       bbdd_bpf_session_stats_json);
	free(discrs);
}

static void bbdd_d_handle_session_del(struct bbdd_d *d,
				      struct bbdd_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	bool bulk;
	int rc;
	char *last_error = NULL;
	size_t num_errors = 0;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, &bulk, d->nl, d->sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	rc = bbdd_d_handle_session_check_bulk(peer, id, bulk, ndiscrs);
	if (rc < 0)
		goto free_discrs;

	for (size_t i = 0; i < ndiscrs; i++) {
		char *error;

		rc = bbdd_d_handle_session_del_one(d, discrs[i], &error);
		if (rc < 0) {
			if (error != NULL) {
				free(last_error);
				last_error = error;
			}
			num_errors++;
		}
	}

	if (num_errors) {
		bbdd_util_jrpc_respond_interr_fmt(peer, id, "%zu/%zu sessions failed to delete. Last recorded error: `%s'",
						  num_errors, ndiscrs,
						  last_error ?: "(unknown error)");
		free(last_error);
		goto free_discrs;
	}

	bbdd_util_jrpc_respond_empty(peer, id);

free_discrs:
	free(discrs);
}

static void bbdd_d_handle_session_show(struct bbdd_d *d,
				       struct bbdd_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	struct bbdd_c_session sess;
	uint32_t *discrs;
	size_t ndiscrs;
	int rc;

	rc = bbdd_d_parse_select_sessions(peer, params_obj, id,
					  &sess, NULL, NULL, d->nl, d->sdir,
					  &discrs, &ndiscrs);
	if (rc < 0)
		return;

	return bbdd_d_handle_session_show_do(peer, id, d->sdir, d->bpf,
					     discrs, ndiscrs);
}

static int bbdd_d_bfdd_handle_add_session_vrf(struct bbdd_d *d,
					      struct bbdd_c_session *csess,
					      char **error)
{
	struct bbdd_d_session *dsess;
	uint32_t discr;
	bool changed;
	int rc;

	/* We wouldn't mind getting a zero discr and allocating ourselves, but
	 * it's not clear how it should work. We are getting a message that a
	 * session is supposed to be added. The session already exists in bfdd,
	 * and has a discriminator assigned. Even if it didn't, there's no
	 * mechanism to report back to bfdd what value we assigned. So best to
	 * just expect the value to be given. */
	if (!csess->discr_seen) {
		bbdd_util_fmterr(error, "missing local discriminator");
		rc = -EINVAL;
		goto invalid;
	}
	discr = csess->discr;

	if (csess->netif.ifindex_seen || csess->netif.name_seen) {
		rc = bbdd_d_session_validate_netif(&csess->netif, error);
		if (rc != 0)
			goto invalid;
	}

	dsess = bbdd_sess_dir_get_session(d->sdir, discr);
	if (dsess == NULL) {
		rc = bbdd_d_session_add(d, csess, error);
		if (rc != 0)
			goto no_session;
		return 0;
	}

	/* Update existing session. */
	rc = bbdd_d_session_apply_c(dsess, csess, d->nl, &changed, error);
	if (rc != 0)
		goto interr;

	if (dsess->hold != NULL)
		return 0;

	rc = bbdd_bpf_session_update(d->bpf, dsess, error);
	if (rc != 0)
		goto interr;

	if (changed)
		bbdd_d_session_state_changed(dsess, d->bpf, d->mon, d->bfdd);
	return 0;

invalid:
	++d->diag_stats.dp_invalid_message;
	return rc;

interr:
	++d->diag_stats.dp_internal_error;
	return rc;

no_session:
	++d->diag_stats.dp_no_session;
	return rc;
}

static int bbdd_d_bfdd_handle_add_session(struct bbdd_d *d,
					  const struct bfddp_message *msg,
					  char **error)
{
	struct bbdd_c_session csess;
	int rc;

	rc = bbdd_bfdd_session_msg_to_c(msg, &csess, error);
	if (rc == -EMSGSIZE)
		++d->diag_stats.dp_invalid_message_length;
	if (rc != 0)
		return -1;

	return bbdd_d_bfdd_handle_add_session_vrf(d, &csess, error);
}

static int __bbdd_d_bfdd_check_length(struct bbdd_d *d,
				      unsigned int length,
				      unsigned int exp_len,
				      const char *where,
				      char **error)
{
	if (length == exp_len)
		return 0;

	++d->diag_stats.dp_invalid_message_length;
	bbdd_util_fmterr(error, "%s: Invalid length: got %u, expected %u",
			 where, length, exp_len);
	return -EINVAL;
}

#define bbdd_d_bfdd_check_length(D, MSG, PAYLOAD, WHERE, ERROR)		\
	({								\
		const struct bfddp_message *_M = (MSG);			\
		enum bfddp_message_type _BMT = ntohs(_M->header.type);	\
		uint16_t _AL = ntohs(_M->header.length);		\
		uint16_t _EL = sizeof(_M->header) +			\
			       sizeof(_M->data PAYLOAD);		\
									\
		assert(_BMT == WHERE);					\
		__bbdd_d_bfdd_check_length((D), _AL, _EL, #WHERE, (ERROR)); \
	})

static int
bbdd_d_bfdd_handle_delete_session(struct bbdd_d *d,
				  const struct bfddp_message *msg,
				  char **error)
{
	uint32_t discr;
	int rc;

	rc = bbdd_d_bfdd_check_length(d, msg, .session,
				      DP_DELETE_SESSION, error);
	if (rc != 0)
		return rc;

	discr = ntohl(msg->data.session.lid);
	rc = bbdd_d_handle_session_del_one(d, discr, error);
	if (rc != 0) {
		++d->diag_stats.dp_no_session;
		bbdd_util_appenderr(error, "DP_DELETE_SESSION");
	}
	return rc;
}

static int
bbdd_d_bfdd_handle_session_counters(struct bbdd_d *d,
				    const struct bfddp_message *msg,
				    char **error1)
{
	uint32_t discr;
	struct bbdd_prog_session_data_stats stats;
	struct bbdd_d_session *dsess;
	char *error2;
	int rc1, rc2;

	rc1 = bbdd_d_bfdd_check_length(d, msg, .counters_req,
				       DP_REQUEST_SESSION_COUNTERS, error1);
	if (rc1 != 0)
		return rc1;

	discr = ntohl(msg->data.counters_req.lid);

	/* On errors, form a nonsense response, but do respond, so that the
	 * sender doesn't stay hanging. */
	stats = (struct bbdd_prog_session_data_stats) {
		.rx_bytes = UINT64_MAX / 2,
		.rx_packets = UINT64_MAX / 2,
		.tx_bytes = UINT64_MAX / 2,
		.tx_packets = UINT64_MAX / 2,
	};

	dsess = bbdd_sess_dir_get_session(d->sdir, discr);
	if (dsess == NULL) {
		++d->diag_stats.dp_no_session;
		bbdd_util_fmterr(error1, "DP_REQUEST_SESSION_COUNTERS: no session for discr %u",
				 discr);
		rc1 = -ENOENT;
		goto reply;
	}

	rc1 = bbdd_bpf_session_stats_fill(d->bpf, discr, &stats, error1);
	if (rc1 != 0) {
		++d->diag_stats.dp_internal_error;
		bbdd_util_appenderr(error1, "DP_REQUEST_SESSION_COUNTERS");
		goto reply;
	}

reply:
	rc2 = bbdd_bfdd_reply_counters(d->bfdd, msg->header.id, discr, &stats,
				      &error2);
	if (rc2 != 0) {
		++d->diag_stats.dp_buffer_error;
		bbdd_util_appenderr(&error2, "reply DP_REQUEST_SESSION_COUNTERS");
	}

	return bbdd_util_pickerr(rc1, error1, rc2, &error2);
}

static int bbdd_d_bfdd_handle_echo_request(struct bbdd_d *d,
					   const struct bfddp_message *msg,
					   char **error)
{
	int rc;

	fprintf(stderr, "Handle echo\n"); // xxx

	rc = bbdd_d_bfdd_check_length(d, msg, .echo, ECHO_REQUEST, error);
	if (rc != 0)
		return rc;

	return bbdd_bfdd_reply_echo(d->bfdd, msg->header.id, &msg->data.echo,
				    error);
}

void bbdd_d_bfdd_mon_send(struct bbdd_mon *mon, const struct bfddp_message *msg)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_bfdd;
	struct json_object *jmsg;
	char *error;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	jmsg = bbdd_bfdd_msg_format_mon(msg, &error);
	if (jmsg == NULL)
		return bbdd_mon_senderr(mon, &error,
					"Failed to format bfdd monitor message");

	bbdd_mon_send(mon, jmsg, topic);
	json_object_put(jmsg);
}

static void __bbdd_d_bfdd_message_cb(struct bbdd_d *d,
				     struct bbdd_bfdd *bfdd,
				     struct bfddp_message *msg)
{
	enum bfddp_message_type bmt;
	char *error;
	int rc;

	if (msg->header.version != 1) {
		++d->diag_stats.dp_wrong_version_number;
		bbdd_util_fmterr(&error, "bfdd: Wrong message version number %d",
				 msg->header.version);
		goto senderr;
	}

	bbdd_d_bfdd_mon_send(d->mon, msg);

	/* This is called from bbdd-bfdd for individual bfdd messages. When we
	 * return error, the sockerr callback is called and causes the socket to
	 * close, but does not shut the daemon down. */

	bmt = ntohs(msg->header.type);
	switch (bmt) {
	case DP_ADD_SESSION:
		rc = bbdd_d_bfdd_handle_add_session(d, msg, &error);
		break;

	case DP_DELETE_SESSION:
		rc = bbdd_d_bfdd_handle_delete_session(d, msg, &error);
		break;

	case DP_REQUEST_SESSION_COUNTERS:
		rc = bbdd_d_bfdd_handle_session_counters(d, msg, &error);
		break;

	case ECHO_REQUEST:
		rc = bbdd_d_bfdd_handle_echo_request(d, msg, &error);
		break;

	/* We send no ECHO_REQUESTS ourselves, so we shouldn't be getting
	 * ECHO_REPLY. The rest are outgoing messages that BFDD shouldn't be
	 * sending to us. */
	case ECHO_REPLY:
	case BFD_SESSION_COUNTERS:
	case BFD_STATE_CHANGE:
	/* Whatever this is. */
	default:
		++d->diag_stats.dp_invalid_message_type;
		bbdd_util_fmterr(&error, "bfdd: Invalid message type %d", bmt);
		rc = -1;
		break;
	}

	if (rc == 0)
		return;

senderr:
	bbdd_mon_senderr(d->mon, &error, "bfdd");
}

static int bbdd_d_bfdd_message_cb(struct bbdd_bfdd *bfdd,
				  struct bfddp_message *msg,
				  void *data, char **)
{
	struct bbdd_d *d = data;

	__bbdd_d_bfdd_message_cb(d, bfdd, msg);
	return 0;
}

static void bbdd_d_bfdd_sockerr_cb(struct bbdd_bfdd *bfdd, const char *error,
				   void *data)
{
	struct bbdd_d *d = data;

	// xxx monitor event, when we have a monitor bus
	fprintf(stderr, "BFD socket closed%c%s\n",
		error ? ':' : '.', error ?: "");

	assert(d->bfdd == bfdd);
	bbdd_bfdd_close(d->bfdd);
	d->bfdd = NULL;
}

static void bbdd_d_bfdd_hangup_cb(struct bbdd_bfdd *bfdd, void *data)
{
	bbdd_d_bfdd_sockerr_cb(bfdd, NULL, data);
}

struct bbdd_d_bfdd_connect_ctx {
	struct bbdd_d *d;
	struct bbdd_sock peer;
	struct json_object *id;
};

static void bbdd_d_bfdd_connected_cb(struct bbdd_bfdd *bfdd, void *data)
{
	struct bbdd_d_bfdd_connect_ctx *cctx = data;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Connected.\n");
	bbdd_util_jrpc_respond_empty(&cctx->peer, cctx->id);
}

static void bbdd_d_bfdd_connect_fail_cb(struct bbdd_bfdd *bfdd, char **error,
					void *data)
{
	struct bbdd_d_bfdd_connect_ctx *cctx = data;
	struct bbdd_d *d = cctx->d;

	fprintf(stderr, "Failed to connect to BFD: %s\n", *error);
	bbdd_util_jrpc_respond_interr_err(&cctx->peer, cctx->id, error);

	assert(d->bfdd == bfdd);
	bbdd_bfdd_close(d->bfdd);
	d->bfdd = NULL;
}

static void bbdd_d_bfdd_connect_free_cb(void *data)
{
	struct bbdd_d_bfdd_connect_ctx *cctx = data;

	json_object_put(cctx->id);
	free(cctx);
}

static int bbdd_d_bfdd_connect_unix(struct bbdd_d *d,
				    struct bbdd_sock *peer,
				    struct json_object *id,
				    const char *path,
				    char **error)
{
	struct bbdd_d_bfdd_connect_ctx *cctx;
	struct bbdd_bfdd_cbs cbs;
	int rc;

	if (d->bfdd) {
		bbdd_util_fmterr(error, "Already connected to a BFD daemon");
		return -1;
	}

	cctx = malloc(sizeof(*cctx));
	if (cctx == NULL) {
		bbdd_util_fmterr(error, "%m");
		return -ENOMEM;
	}
	*cctx = (struct bbdd_d_bfdd_connect_ctx) {
		.d = d,
		.peer = *peer,
		.id = json_object_get(id),
	};

	cbs = (struct bbdd_bfdd_cbs) {
		.conn_cb_data = cctx,
		.connected_cb = bbdd_d_bfdd_connected_cb,
		.connect_failed_cb = bbdd_d_bfdd_connect_fail_cb,
		.connect_free_cb = bbdd_d_bfdd_connect_free_cb,

		.sock_cb_data = d,
		.hangup_cb = bbdd_d_bfdd_hangup_cb,
		.sockerr_cb = bbdd_d_bfdd_sockerr_cb,
		.message_cb = bbdd_d_bfdd_message_cb,
		.sock_free_cb = NULL,
	};

	d->bfdd = bbdd_bfdd_open(path, d->pctx, &cbs, error);
	if (d->bfdd == NULL) {
		rc = -ENOMEM;
		goto cctx_free;
	}

	return 0;

cctx_free:
	free(cctx);
	return rc;
}

static void bbdd_d_handle_bfdd_connect(struct bbdd_d *d,
				       struct bbdd_sock *peer,
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
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	proto = json_object_get_string(values[pol_proto]);
	addr = json_object_get_string(values[pol_addr]);
	port = json_object_get_string(values[pol_port]);

	af = bbdd_sock_af_from_str(proto, &error);
	if (af < 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	if (af != AF_UNIX)
		return bbdd_util_jrpc_respond_inv_params(peer, id, "Only `unix' protocol supported");

	if (port != NULL)
		return bbdd_util_jrpc_respond_inv_params(peer, id, "`unix' address schema doesn't support ports");

	rc = bbdd_d_bfdd_connect_unix(d, peer, id, addr, &error);
	if (rc < 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	/* Response for successful cases is handled asynchronously. */
}

static void bbdd_d_handle_bfdd_connected(struct bbdd_d *d,
					 struct bbdd_sock *peer,
					 struct json_object *params_obj,
					 struct json_object *id)
{
	struct json_object *obj;
	bool connected;
	char *error;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	connected = d->bfdd != NULL && bbdd_bfdd_is_connected(d->bfdd);

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return bbdd_util_jrpc_respond_memerr(peer, id);

	if (json_object_object_add(obj, "result",
				   json_object_new_boolean(connected)) != 0) {
		json_object_put(obj);
		return bbdd_util_jrpc_respond_memerr(peer, id);
	}

	bbdd_util_jrpc_send(peer, obj);
	json_object_put(obj);
}

static void bbdd_d_handle_bfdd_disconnect(struct bbdd_d *d,
					  struct bbdd_sock *peer,
					  struct json_object *params_obj,
					  struct json_object *id)
{
	char *error = NULL;
	int rc;

	rc = bbdd_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	if (d->bfdd == NULL) {
		bbdd_util_jrpc_respond_empty(peer, id);
		return;
	}

	bbdd_bfdd_close(d->bfdd);
	d->bfdd = NULL;

	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: Disconnected.\n");

	bbdd_util_jrpc_respond_empty(peer, id);
}

void bbdd_d_handle_monitor_subscribe(struct bbdd_mon *mon,
				     struct bbdd_sock *peer,
				     struct json_object *params_obj,
				     struct json_object *id)
{
	enum {
		pol_topics,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_topics] = { .key = "topics", .type = json_type_array,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	struct bbdd_mon_topics topics = {};
	struct json_object *topics_arr;
	char *error = NULL;
	int rc;

	rc = bbdd_jrpc_dissect(params_obj, policy, seen, values,
			       ARRAY_SIZE(policy), &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	topics_arr = values[pol_topics];

	rc = bbdd_jrpc_validate_array(topics_arr, json_type_string, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);

	size_t len = json_object_array_length(topics_arr);
	if (len == 0)
		return bbdd_util_jrpc_respond_inv_params(peer, id,  "topics: list must be non-empty");

	for (size_t i = 0; i < len; i++) {
		struct json_object *elm;

		elm = json_object_array_get_idx(topics_arr, i);
		const char *name = json_object_get_string(elm);

#define MATCH_TOPIC(NAME, ALL)						\
		if (strcmp(name, #NAME) == 0) {				\
			topics.enabled[BBDD_MON_TOPIC_ ## NAME] = true;	\
			continue;					\
		}
		BBDD_MON_TOPICS(MATCH_TOPIC)
#undef MATCH_TOPIC

		bbdd_util_fmterr(&error, "Unknown topic `%s'", name);
		return bbdd_util_jrpc_respond_inv_params_err(peer, id, &error);
	}

	rc = bbdd_mon_subscribe(mon, peer, topics, &error);
	if (rc != 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &error);

	bbdd_util_jrpc_respond_empty(peer, id);
}

static void bbdd_d_handle_unhandled(struct bbdd_sock *peer,
				    const char *method,
				    struct json_object *id)
{
	bbdd_util_jrpc_respond(peer, bbdd_jrpc_new_error_method_nf(id, method));
}

static void bbdd_d_handle_method(struct bbdd_sock *peer,
				 const char *method,
				 struct json_object *params_obj,
				 struct json_object *id,
				 void *data)
{
	struct bbdd_d *d = data;

	if (strcmp(method, "stop") == 0)
		bbdd_d_handle_stop(d->pctx, peer, params_obj, id);
	else if (strcmp(method, "ping") == 0)
		bbdd_d_handle_ping(peer, params_obj, id);
	else if (strcmp(method, "global-stats-diag") == 0)
		bbdd_d_handle_global_stats_get(d, peer, params_obj, id);
	else if (strcmp(method, "session-show") == 0)
		bbdd_d_handle_session_show(d, peer, params_obj, id);
	else if (strcmp(method, "session-add") == 0)
		bbdd_d_handle_session_add(d, peer, params_obj, id);
	else if (strcmp(method, "session-set") == 0)
		bbdd_d_handle_session_set(d, peer, params_obj, id);
	else if (strcmp(method, "session-del") == 0)
		bbdd_d_handle_session_del(d, peer, params_obj, id);
	else if (strcmp(method, "session-stats-diag") == 0)
		bbdd_d_handle_session_stats_diag(d, peer, params_obj, id);
	else if (strcmp(method, "session-stats") == 0)
		bbdd_d_handle_session_stats(d, peer, params_obj, id);
	else if (strcmp(method, "bfdd-connect") == 0)
		bbdd_d_handle_bfdd_connect(d, peer, params_obj, id);
	else if (strcmp(method, "bfdd-connected") == 0)
		bbdd_d_handle_bfdd_connected(d, peer, params_obj, id);
	else if (strcmp(method, "bfdd-disconnect") == 0)
		bbdd_d_handle_bfdd_disconnect(d, peer, params_obj, id);
	else if (strcmp(method, "monitor-subscribe") == 0)
		bbdd_d_handle_monitor_subscribe(d->mon, peer, params_obj, id);
	else
		bbdd_d_handle_unhandled(peer, method, id);
}

static int bbdd_d_ctl_recv(struct bbdd_poll_ctx *pctx, short, void *arg,
			   char **)
{
	struct bbdd_d *d = arg;

	bbdd_util_ctl_activity(&d->ctl, bbdd_d_handle_method, d);
	return 0;
}

static int bbdd_d_raise_nofile(char **error)
{
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		bbdd_util_fmterr(error, "Failed to get RLIMIT_NOFILE: %m");
		return -1;
	}

	rlim.rlim_cur = rlim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		bbdd_util_fmterr(error, "Failed to set RLIMIT_NOFILE: %m");
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

		err = bbdd_nl_add_qdisc_fq(nl, ifindex, parent, 0, error);
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
		goto err;

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
err:
	bbdd_util_appenderr(error, "Failed to create veth pair `%s'<->`%s'",
			    bbdd_d_veth_rx_name, bbdd_d_veth_tx_name);
	return err;
}

static int bbdd_d_do_start(const struct bbdd_mon_topics topics)
{
	struct bbdd_d d = {};
	const struct bbdd_bpf_cbs bpf_cbs = {
		.data = &d,
		.session_state_changed = bbdd_d_session_state_changed_cb,
		.match_session = bbdd_d_match_session_cb,
		.find_session = bbdd_d_find_session_cb,
	};
	uint32_t veth_rx_ifindex;
	uint32_t veth_tx_ifindex;
	struct bbdd_bpf_global_config bpf_conf;
	bool failed = true;
	char *error;
	int err;

	openlog("bbdd", LOG_PID | LOG_CONS, LOG_USER);

	if (bbdd_d_raise_nofile(&error) < 0)
		goto closelog;

	d.nl = bbdd_nl_create(&error);
	if (d.nl == NULL)
		goto closelog;

	d.pctx = bbdd_poll_init(&error);
	if (d.pctx == NULL)
		goto nl_destroy;

	d.sdir = bbdd_sess_dir_create(&error);
	if (d.sdir == NULL)
		goto poll_fini;

	d.mon = bbdd_mon_init(&error);
	if (d.mon == NULL)
		goto sess_dir_destroy;

	err = bbdd_mon_subscribe_cb(d.mon, bbdd_c_monitor_dispatch, NULL,
				    topics, &error);
	if (err != 0)
		goto mon_fini;

	err = bbdd_d_start_init_veth(d.nl,
				     &veth_rx_ifindex,
				     &veth_tx_ifindex,
				     &error);
	if (err)
		goto mon_fini;

	bpf_conf = (struct bbdd_bpf_global_config) {
		.veth_rx_ifindex = veth_rx_ifindex,
		.veth_tx_ifindex = veth_tx_ifindex,
	};

	d.bpf = bbdd_bpf_create(&bpf_cbs, d.pctx, d.nl, &bpf_conf, d.mon,
				&error);
	if (d.bpf == NULL)
		goto fini_veth;

	err = bbdd_sock_open_d(&d.ctl, bbdd_env.sockdir, &error);
	if (err != 0)
		goto bpf_destroy;

	err = bbdd_poll_set_fd(d.pctx, d.ctl.fd, POLLIN,
			       bbdd_d_ctl_recv, &d, &error);
	if (err != 0)
		goto sock_close_d;

	err = bbdd_poll_set_signals(d.pctx, &error);
	if (err != 0)
		goto sock_close_d;

	err = bbdd_poll_loop(d.pctx, &error);
	if (err != 0)
		goto cleanup;

	failed = false;

cleanup:
	bbdd_mon_send_monitor_end(d.mon);

	if (d.bfdd != NULL)
		bbdd_bfdd_close(d.bfdd);

	bbdd_poll_unset_signals(d.pctx);
sock_close_d:
	bbdd_sock_close_d(&d.ctl);
bpf_destroy:
	bbdd_bpf_destroy(d.bpf);
fini_veth:
	bbdd_d_start_fini_veth(d.nl);
mon_fini:
	bbdd_mon_fini(d.mon);
sess_dir_destroy:
	bbdd_sess_dir_destroy(d.sdir);
poll_fini:
	bbdd_poll_fini(d.pctx);
nl_destroy:
	bbdd_nl_destroy(d.nl);
closelog:
	closelog();

	if (failed)
		bbdd_util_printerr(&error, "Error");
	return err;
}

int bbdd_d_start(int argc, char **argv)
{
	struct bbdd_mon_topics topics = {};

	if (argc > 0 && strcmp(*argv, "help") == 0) {
		fprintf(stderr, "Usage: bbdd start [monitor [topics...]]\n");
		return 0;
	}

	if (argc > 0 && strcmp(*argv, "monitor") == 0) {
		int rc;

		NEXT_ARG_FWD();
		rc = bbdd_c_monitor_parse_topics(argc, argv, &topics);
		if (rc != 0)
			return rc;
		return bbdd_d_do_start(topics);
	}

	if (argc > 0) {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	}

	topics.enabled[BBDD_MON_TOPIC_error] = true;
	return bbdd_d_do_start(topics);
}
