/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json_object.h>

/* bfddp.h */
struct bbdd_c_session;

/* bbdd-prog-stat.h */
struct bbdd_prog_session_data_stats;

/* bbdd-poll.c */
struct bbdd_poll_ctx;

/* bfddp_packet.h */
struct bfddp_echo;
struct bfddp_message;
struct bfddp_session_cumulus;

/* bbdd-bfdd.c */
struct bbdd_bfdd;

#define BBDD_BFDD_DEFAULT_ADDR "unix:/var/run/frr/bfdd_dplane.sock"

struct bbdd_bfdd_cbs {
	void *conn_cb_data;
	void (*connected_cb)(struct bbdd_bfdd *, void *);
	void (*connect_failed_cb)(struct bbdd_bfdd *, char **, void *);
	void (*connect_free_cb)(void *);

	void *sock_cb_data;
	void (*sockerr_cb)(struct bbdd_bfdd *, const char *, void *);
	int (*message_cb)(struct bbdd_bfdd *, struct bfddp_message *,
			  void *, char **);
	void (*sock_free_cb)(void *);
};

struct bbdd_bfdd *bbdd_bfdd_open(const char *path,
				 struct bbdd_poll_ctx *pctx,
				 const struct bbdd_bfdd_cbs *cbs,
				 char **error);
void bbdd_bfdd_close(struct bbdd_bfdd *bfdd);

bool bbdd_bfdd_is_connected(const struct bbdd_bfdd *bfdd);

int bbdd_bfdd_reply_counters(struct bbdd_bfdd *bfdd,
			     uint16_t msg_id, uint32_t discr,
			     const struct bbdd_prog_session_data_stats *stats,
			     char **error);
int bbdd_bfdd_reply_echo(struct bbdd_bfdd *bfdd,
			 uint16_t msg_id,
			 const struct bfddp_echo *in_echo, char **error);

int bbdd_bfdd_session_msg_to_c(const struct bfddp_message *msg,
			       struct bbdd_c_session *csess,
			       char **error);

struct json_object *bbdd_bfdd_msg_format_mon(const struct bfddp_message *msg,
					     char **error);
