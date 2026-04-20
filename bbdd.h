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
} bbdd_env;

int bbdd_jrpc_send(struct bbdd_sock *sock, struct json_object *obj);

/* bbdd-c.c */

int bbdd_c_stop(int argc, char **argv);
int bbdd_c_ping(int argc, char **argv);
int bbdd_c_session(int argc, char **argv);
int bbdd_c_global(int argc, char **argv);
int bbdd_c_bfdd(int argc, char **argv);

#define BBDD_C_SESSION_FLAGS(X)		\
	X(MULTIHOP, multihop)		\
	X(DEMAND, demand)		\
	X(CBIT, cbit)			\
	X(IPV6, ipv6)			\
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

struct bbdd_c_session {
	struct bbdd_c_session_flags flags;
	char src[INET6_ADDRSTRLEN];	int src_af;
	char dst[INET6_ADDRSTRLEN];	int dst_af;
	uint32_t discr;			int discr_seen;
	uint32_t min_tx_us;		int min_tx_us_seen;
	uint32_t min_rx_us;		int min_rx_us_seen;
	uint32_t hold_time;		int hold_time_seen;
	uint8_t ttl;			int ttl_seen;
	uint8_t detect_mult;		int detect_mult_seen;
	uint32_t ifindex;		int ifindex_seen;
	char ifname[IFNAMSIZ];		int ifname_seen;
};

struct json_object *bbdd_c_jrpc_session_obj(const struct bbdd_c_session *sess);

/* bbdd-d.c */

#define BBDD_D_GLOBAL_DIAG_STATS(FIELD)		\
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

struct bbdd_d_session_data {
	uint32_t discr;
	uint8_t detect_mult;
	uint32_t min_tx_us;
	uint32_t min_rx_us;
	struct bbdd_d_session_state_end state;
};

/* For carrying state information decoded from RPC. Most local session-specific
 * information is carried in bbdd_c_session. This contains the state & diag bits
 * for local session, and known remote session configuration. */
struct bbdd_c_session_state {
	struct bbdd_d_session_state_end local;
	struct bbdd_d_session_data remote;
};

struct bbdd_d_session {
	/* Local session configuration. */
	struct bbdd_d_session_flags flags;
	struct bbdd_sockaddr src;
	struct bbdd_sockaddr dst;

	uint32_t hold_time;
	uint8_t ttl;
	uint32_t ifindex;

	struct bbdd_d_session_data local;

	/* Remote session data. */
	struct bbdd_d_session_data remote;
};

int bbdd_d_start(int argc, char **argv);

int bbdd_d_jrpc_dissect_session_one(struct json_object *obj,
				    struct bbdd_c_session *sess,
				    char **error);

const char *bbdd_d_bfd_state_to_str(enum bbdd_bfd_pkt_state sv);
int bbdd_d_bfd_state_from_str(const char *str, enum bbdd_bfd_pkt_state *sv);

const char *bbdd_d_bfd_diag_to_str(enum bbdd_bfd_pkt_diag dv);
int bbdd_d_bfd_diag_from_str(const char *str, enum bbdd_bfd_pkt_diag *dv);

struct json_object *bbdd_d_session_json(struct bbdd_d_session *dsess);
