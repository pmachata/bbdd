/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <json-c/json_object.h>

#include "bbdd-sess.h"

#include "bbdd-mon.i"

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
	struct bbdd_sess_flags flags;
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

int bbdd_c_stop(int argc, char **argv);
int bbdd_c_echo(int argc, char **argv);
int bbdd_c_session(int argc, char **argv);
int bbdd_c_global(int argc, char **argv);
int bbdd_c_bfdd(int argc, char **argv, const struct bbdd_mon_topics *topics);

int bbdd_c_monitor(int argc, char **argv, const struct bbdd_mon_topics *topics);
void bbdd_c_monitor_dispatch(struct json_object *msg, void *data);

struct json_object *bbdd_c_jrpc_session_obj(const struct bbdd_c_session *sess);
struct json_object *bbdd_c_jrpc_addr_obj(const char *addr, int af);
