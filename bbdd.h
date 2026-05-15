/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>
#include <json-c/json_object.h>

#include "bbdd-nl.h"
#include "bbdd-pkt.h"
#include "bbdd-sock.h"

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* bbdd.c */

extern struct bbdd_env {
	const char *sockdir;
	int verbosity;
	bool show_json;
	bool numeric;
	bool timestamp;
	bool mon_eager;
} bbdd_env;

/* bbdd-bpf.c */

struct bbdd_bpf;

/* bbdd-mon.c */

struct bbdd_mon;
struct bbdd_mon_topics;

/* bbdd-nl.c */

struct bbdd_nl;

/* bbdd-c.c */

int bbdd_c_stop(int argc, char **argv);
int bbdd_c_ping(int argc, char **argv);
int bbdd_c_session(int argc, char **argv);
int bbdd_c_global(int argc, char **argv);
int bbdd_c_bfdd(int argc, char **argv);
int bbdd_c_monitor(int argc, char **argv);
int bbdd_c_monitor_parse_topics(int argc, char **argv,
				struct bbdd_mon_topics *topics);
void bbdd_c_monitor_dispatch(struct json_object *msg, void *data);

#define BBDD_C_SESSION_FLAGS(X)		\
	X(MULTIHOP, multihop)		\
	X(CBIT, cbit)			\
	X(PASSIVE, passive)		\
	X(SHUTDOWN, shutdown)		\
	/**/

#define BBDD_C_SESSION_EXPAND_ENUM(NAME, name, ...)	\
	bbdd_c_session_flag_ ## name,
#define BBDD_C_SESSION_EXPAND_PLUS1(...) + 1

enum bbdd_c_session_flag_ix {
	BBDD_C_SESSION_FLAGS(BBDD_C_SESSION_EXPAND_ENUM)
};

enum {
	bbdd_c_session_nflags =
		BBDD_C_SESSION_FLAGS(BBDD_C_SESSION_EXPAND_PLUS1)
};

#undef BBDD_C_SESSION_EXPAND_PLUS1
#undef BBDD_C_SESSION_EXPAND_ENUM

struct bbdd_c_session_flag {
	bool value;
	bool seen;
};

#define BBDD_C_SESSION_EXPAND_FIELD(NAME, name, ...)	\
	struct bbdd_c_session_flag name;

struct bbdd_c_session_flags {
	union {
		struct bbdd_c_session_flag flags[bbdd_c_session_nflags];
		struct {
			BBDD_C_SESSION_FLAGS(BBDD_C_SESSION_EXPAND_FIELD)
		};
	};
};

#undef BBDD_C_SESSION_EXPAND_FIELD

static inline bool bbdd_c_session_flag_isset(struct bbdd_c_session_flag flag)
{
	return flag.seen && flag.value;
}

const char *bbdd_c_session_flag_name(enum bbdd_c_session_flag_ix flag);

struct bbdd_c_session_netif {
	/* Request to unset interface, or explicit request to match
	 * non-interfaced sessions. When set, name_seen and ifindex_seen are
	 * both unset. */
	bool unset;
	char name[IFNAMSIZ];		int name_seen;
	uint32_t ifindex;		int ifindex_seen;
};

struct bbdd_c_session_vrf {
	struct bbdd_c_session_netif netif;
	uint32_t table;			int table_seen;
};

struct bbdd_c_session_addr {
	/* Request to unset address, or explicit request to match sessions
	 * without address. When set, af == 0. */
	bool unset;
	char str[INET6_ADDRSTRLEN];	int af;
};

struct bbdd_c_session {
	struct bbdd_c_session_flags flags;
	uint32_t discr;			int discr_seen;
	uint32_t min_tx_us;		int min_tx_us_seen;
	uint32_t min_rx_us;		int min_rx_us_seen;
	uint32_t hold_time_us;		int hold_time_us_seen;
	uint8_t ttl;			int ttl_seen;
	uint8_t detect_mult;		int detect_mult_seen;
	struct bbdd_c_session_addr src;
	struct bbdd_c_session_addr dst;
	struct bbdd_c_session_netif netif;
	struct bbdd_c_session_vrf vrf;
};

struct json_object *bbdd_c_jrpc_session_obj(const struct bbdd_c_session *sess);
struct json_object *bbdd_c_jrpc_addr_obj(const char *addr, int af);

/* bbdd-d.c */

#define BBDD_D_GLOBAL_DIAG_STATS(FIELD)		\
	FIELD(dp_wrong_version_number)		\
	FIELD(dp_invalid_message_length)	\
	FIELD(dp_invalid_message_type)		\
	FIELD(dp_invalid_message)		\
	FIELD(dp_internal_error)		\
	FIELD(dp_no_session)			\
	FIELD(dp_buffer_error)			\
	/**/

#define STAT_FIELD(NAME) __u64 NAME;
struct bbdd_d_global_diag_stats {
	BBDD_D_GLOBAL_DIAG_STATS(STAT_FIELD)
};
#undef STAT_FIELD

#define BBDD_D_SESSION_EXPAND_FIELD(NAME, name, ...) bool name;

struct bbdd_d_session_flags {
	union {
		bool flags[bbdd_c_session_nflags];
		struct {
			BBDD_C_SESSION_FLAGS(BBDD_D_SESSION_EXPAND_FIELD)
		};
	};
};

#undef BBDD_C_SESSION_EXPAND_FIELD

struct bbdd_d_session_state_end {
	enum bbdd_bfd_pkt_state state;
	enum bbdd_bfd_pkt_diag diag;
};

struct bbdd_d_session_data_timing {
	uint8_t detect_mult;
	uint32_t min_tx_us;
	uint32_t min_rx_us;
};

struct bbdd_d_session_data {
	uint32_t discr;
	struct bbdd_d_session_data_timing timing;
	struct bbdd_d_session_state_end state;
};

struct bbdd_d_hold;

struct bbdd_d_session {
	/* Local session configuration. */
	struct bbdd_d_session_flags flags;
	struct bbdd_sockaddr src;
	struct bbdd_sockaddr dst;

	uint32_t hold_time_us;
	uint8_t ttl;
	uint32_t ifindex;
	uint32_t vrf_ifindex;

	/* Non-0; table 0 is invalid, so use it to mean `not configured'. */
	uint32_t vrf_table;

	struct bbdd_d_session_data local;
	struct bbdd_d_session_data remote;

	/* Non-NULL while the session hold timer is active. The session is not
	 * yet projected to BPF during this time. */
	struct bbdd_d_hold *hold;
};

int bbdd_d_start(int argc, char **argv);

int bbdd_d_jrpc_dissect_session_one(struct json_object *obj,
				    struct bbdd_c_session *sess,
				    char **error);
int bbdd_d_jrpc_dissect_validate_session(struct json_object *obj,
					 struct bbdd_c_session *sess,
					 const char *what,
					 struct bbdd_nl *nl,
					 char **error);

const char *bbdd_d_bfd_state_to_str(enum bbdd_bfd_pkt_state sv);
int bbdd_d_bfd_state_from_str(const char *str, enum bbdd_bfd_pkt_state *sv);

const char *bbdd_d_bfd_diag_to_str(enum bbdd_bfd_pkt_diag dv);
int bbdd_d_bfd_diag_from_str(const char *str, enum bbdd_bfd_pkt_diag *dv);

int bbdd_d_session_apply_c(struct bbdd_d_session *dsess,
			   const struct bbdd_c_session *csess,
			   struct bbdd_nl *nl,
			   bool *changed, char **error);

/* json-c */
struct json_object;

struct json_object *bbdd_d_session_json(struct bbdd_bpf *bpf,
					struct bbdd_d_session *dsess,
					char **error);
