/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json_object.h>

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
} bbdd_env;

int bbdd_jrpc_send(struct bbdd_sock *sock, struct json_object *obj);

/* bbdd-c.c */

int bbdd_c_stop(int argc, char **argv);
int bbdd_c_ping(int argc, char **argv);
int bbdd_c_session(int argc, char **argv);

struct bbdd_c_session {
	/* Flags. */
	bool multihop;
	bool demand;
	bool cbit;
	bool echo;
	bool ipv6;
	bool passive;
	bool shutdown;
	/* Other fields. */
	const char *src;		int src_af;
	const char *dst;		int dst_af;
	uint32_t lid;			int lid_seen;
	uint32_t min_tx;		int min_tx_seen;
	uint32_t min_rx;		int min_rx_seen;
	uint32_t min_echo_tx;		int min_echo_tx_seen;
	uint32_t min_echo_rx;		int min_echo_rx_seen;
	uint32_t hold_time;		int hold_time_seen;
	uint8_t ttl;			int ttl_seen;
	uint8_t detect_mult;		int detect_mult_seen;
	uint32_t ifindex;		int ifindex_seen;
	const char *ifname;		int ifname_seen;
};

struct json_object *bbdd_c_jrpc_session_obj(struct bbdd_c_session *sess);

/* bbdd-d.c */

int bbdd_d_start(int argc, char **argv);

struct bfddp_session;
int bbdd_d_jrpc_dissect_params_session(struct json_object *obj,
				       struct bfddp_session *sess,
				       char **error);
