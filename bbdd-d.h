/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <json-c/json_object.h>

#include "bbdd-pkt.h"
#include "bbdd-sess.h"
#include "bbdd-sock.h"

/* bbdd-bpf.c */

struct bbdd_bpf;

/* bbdd-mon.c */

struct bbdd_mon;

/* bbdd-nl.c */

struct bbdd_nl;

/* bbdd-c.c */

struct bbdd_c_session;

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

#define STAT_FIELD(NAME) uint64_t NAME;
struct bbdd_d_global_diag_stats {
	BBDD_D_GLOBAL_DIAG_STATS(STAT_FIELD)
};
#undef STAT_FIELD

#define BBDD_D_SESSION_EXPAND_FIELD(NAME, name, ...) bool name;

struct bbdd_d_session_flags {
	union {
		bool flags[bbdd_sess_nflags];
		struct {
			BBDD_SESS_FLAGS(BBDD_D_SESSION_EXPAND_FIELD)
		};
	};
};

#undef BBDD_SESS_EXPAND_FIELD

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
void bbdd_d_handle_monitor_subscribe(struct bbdd_mon *mon,
				     struct bbdd_sock *peer,
				     struct json_object *params_obj,
				     struct json_object *id);

const char *bbdd_d_bfd_state_to_str(enum bbdd_bfd_pkt_state sv);
int bbdd_d_bfd_state_from_str(const char *str, enum bbdd_bfd_pkt_state *sv);

const char *bbdd_d_bfd_diag_to_str(enum bbdd_bfd_pkt_diag dv);
int bbdd_d_bfd_diag_from_str(const char *str, enum bbdd_bfd_pkt_diag *dv);

int bbdd_d_session_apply_c(struct bbdd_d_session *dsess,
			   const struct bbdd_c_session *csess,
			   struct bbdd_nl *nl,
			   bool *changed, char **error);

struct json_object *bbdd_d_session_json(struct bbdd_bpf *bpf,
					struct bbdd_d_session *dsess,
					char **error);
