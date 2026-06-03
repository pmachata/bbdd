/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json_object.h>

#include "bbdd-be.h"

#include "bbdd-bfdd.i"
#include "bbdd-c.i"
#include "bbdd-d.i"
#include "bbdd-mon.i"
#include "bbdd-nl.i"
#include "bfddp_packet.i"
#include "bbdd-poll.i"
#include "bbdd-prog-stat.i"
#include "bbdd-sock.i"

#define BBDD_BFDD_DEFAULT_ADDR "unix:/var/run/frr/bfdd_dplane.sock"

struct bbdd_bfdd_cbs {
	void *conn_cb_data;
	void (*connected_cb)(struct bbdd_bfdd *, void *);
	void (*connect_failed_cb)(struct bbdd_bfdd *, char **, void *);
	void (*connect_free_cb)(void *);

	void *sock_cb_data;
	void (*hangup_cb)(struct bbdd_bfdd *, void *);
	void (*sockerr_cb)(struct bbdd_bfdd *, const char *, void *);
	int (*message_cb)(struct bbdd_bfdd *, struct bfddp_message *,
			  void *, char **);
	void (*sock_free_cb)(void *);
};

struct bbdd_bfdd *bbdd_bfdd_open(const char *path,
				 struct bbdd_poll_ctx *pctx,
				 struct bbdd_mon *mon,
				 const struct bbdd_bfdd_cbs *cbs,
				 char **error);
struct bbdd_bfdd *bbdd_bfdd_open_client(int fd,
					struct bbdd_poll_ctx *pctx,
					struct bbdd_mon *mon,
					const struct bbdd_bfdd_cbs *cbs,
					char **error);
void bbdd_bfdd_close(struct bbdd_bfdd *bfdd);

bool bbdd_bfdd_is_connected(const struct bbdd_bfdd *bfdd);

void bbdd_bfdd_echo_handle_start(struct bbdd_bfdd *bfdd, struct bbdd_sock *peer,
				 struct json_object *id, bool is_dp);
void bbdd_bfdd_echo_handle_reply(struct bbdd_bfdd *bfdd,
				 const struct bfddp_message *msg);

int bbdd_bfdd_send_echo(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			uint64_t time_us, bool is_dp, char **error);
int bbdd_bfdd_reply_echo(struct bbdd_bfdd *bfdd,
			 uint16_t msg_id,
			 const struct bfddp_echo *in_echo,
			 bool is_dp, char **error);
int bbdd_bfdd_send_state_change(struct bbdd_bfdd *bfdd,
				const struct bbdd_d_session *dsess,
				char **error);
int bbdd_bfdd_add_session(struct bbdd_bfdd *bfdd,
			  struct bbdd_nl *nl,
			  const struct bbdd_c_session *csess,
			  uint16_t msg_id, char **error);
int bbdd_bfdd_del_session(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			  uint32_t discr, char **error);
int bbdd_bfdd_request_counters(struct bbdd_bfdd *bfdd, uint16_t msg_id,
			       uint32_t discr, char **error);
int bbdd_bfdd_reply_counters(struct bbdd_bfdd *bfdd,
			     uint16_t msg_id, uint32_t discr,
			     const struct bbdd_prog_session_data_stats *stats,
			     char **error);

int bbdd_bfdd_session_msg_to_c(const struct bfddp_message *msg,
			       struct bbdd_c_session *csess,
			       char **error);

int bbdd_bfdd_format_state_change(const struct bfddp_state_change *sc,
				  const char *method,
				  struct bbdd_mon_message *mon_msg,
				  char **error);

void bbdd_bfdd_mon_send_i(struct bbdd_mon *mon, const struct bfddp_message *msg);
void bbdd_bfdd_mon_send_o(struct bbdd_mon *mon, const struct bfddp_message *msg);
