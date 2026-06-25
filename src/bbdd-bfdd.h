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
#include "bbdd-ssk.i"

#define BBDD_BFDD_DEFAULT_ADDR "unix:/var/run/frr/bfdd_dplane.sock"

struct bbdd_bfdd_cbs {
	void *data;
	/* Fired when the bfddp peer is gone (hangup or socket error). The
	 * user is expected to call bbdd_bfdd_close_{c,d} from here. */
	void (*done_cb)(void *);
	int (*message_cb)(const struct bfddp_message *, void *, char **);
};

/* Client side (data-plane role): connect to a BFD daemon at `path'. */
struct bbdd_bfdd_c *bbdd_bfdd_open_c(const char *path,
				     struct bbdd_poll_ctx *pctx,
				     struct bbdd_mon *mon,
				     const struct bbdd_bfdd_cbs *cbs,
				     char **error);
void bbdd_bfdd_close_c(struct bbdd_bfdd_c *c);

/* Server side (BFD-daemon role): attach to an ssk peer that the caller
 * (e.g. the bridge) has already accepted. The peer remains owned by the
 * caller's ssk_d. */
struct bbdd_bfdd_d *bbdd_bfdd_attach_d(struct bbdd_ssk_peer *peer,
				       struct bbdd_poll_ctx *pctx,
				       struct bbdd_mon *mon,
				       const struct bbdd_bfdd_cbs *cbs,
				       char **error);
void bbdd_bfdd_close_d(struct bbdd_bfdd_d *d);

/* Client side (data-plane role) operations. */
bool bbdd_bfdd_c_is_connected(const struct bbdd_bfdd_c *c);
void bbdd_bfdd_c_echo_handle_start(struct bbdd_bfdd_c *c,
				   struct bbdd_ssk_peer *peer,
				   struct json_object *id);
void bbdd_bfdd_c_echo_handle_reply(struct bbdd_bfdd_c *c,
				   const struct bfddp_message *msg);
int bbdd_bfdd_c_reply_echo(struct bbdd_bfdd_c *c, uint16_t msg_id,
			   const struct bfddp_echo *in_echo, char **error);
int bbdd_bfdd_c_send_state_change(struct bbdd_bfdd_c *c,
				  const struct bbdd_d_session *dsess,
				  char **error);
int bbdd_bfdd_c_reply_counters(struct bbdd_bfdd_c *c,
			       uint16_t msg_id, uint32_t discr,
			       const struct bbdd_prog_session_data_stats *stats,
			       char **error);

/* Server side (BFD-daemon role) operations. */
bool bbdd_bfdd_d_is_connected(const struct bbdd_bfdd_d *d);
void bbdd_bfdd_d_echo_handle_start(struct bbdd_bfdd_d *d,
				   struct bbdd_ssk_peer *peer,
				   struct json_object *id);
void bbdd_bfdd_d_echo_handle_reply(struct bbdd_bfdd_d *d,
				   const struct bfddp_message *msg);
int bbdd_bfdd_d_reply_echo(struct bbdd_bfdd_d *d, uint16_t msg_id,
			   const struct bfddp_echo *in_echo, char **error);
int bbdd_bfdd_d_add_session(struct bbdd_bfdd_d *d, struct bbdd_nl *nl,
			    const struct bbdd_c_session *csess,
			    uint16_t msg_id, char **error);
int bbdd_bfdd_d_del_session(struct bbdd_bfdd_d *d, uint16_t msg_id,
			    uint32_t discr, char **error);
int bbdd_bfdd_d_request_counters(struct bbdd_bfdd_d *d, uint16_t msg_id,
				 uint32_t discr, char **error);

int bbdd_bfdd_session_msg_to_c(const struct bfddp_message *msg,
			       struct bbdd_c_session *csess,
			       char **error);

int bbdd_bfdd_format_state_change(const struct bfddp_state_change *sc,
				  const char *method,
				  struct bbdd_mon_message *mon_msg,
				  char **error);

void bbdd_bfdd_mon_send_i(struct bbdd_mon *mon, const struct bfddp_message *msg);
void bbdd_bfdd_mon_send_o(struct bbdd_mon *mon, const struct bfddp_message *msg);
