/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <json-c/json_object.h>
#include "bbdd-sock.h"
#include "bbdd-mon.i"
#include "bbdd-poll.i"
#include "bbdd-ssk.i"

struct bbdd_ssk_peer;

struct bbdd_ssk_cbs {
	int (*rx_cb)(struct bbdd_ssk_peer *peer, const char *buf, size_t len,
		     void *data, char **error);
	void (*done_cb)(struct bbdd_ssk_peer *peer, void *data);
	void *data;

	struct bbdd_ssk_cbs *next;
	struct bbdd_ssk_cbs *prev;
};

struct bbdd_ssk_d *bbdd_ssk_open_d(struct bbdd_poll_ctx *pctx,
				   const struct bbdd_sockaddr *bsa,
				   struct bbdd_mon *mon,
				   uint32_t tx_cap,
				   char **error);
void bbdd_ssk_close_d(struct bbdd_ssk_d *ssd);
int bbdd_ssk_d_accept(struct bbdd_ssk_d *ssd, struct bbdd_ssk_cbs cbs,
		      struct bbdd_ssk_peer **ret_peer,
		      char **error);
int bbdd_ssk_d_fd(struct bbdd_ssk_d *ssd);

struct bbdd_ssk_c *bbdd_ssk_open_c(struct bbdd_poll_ctx *pctx,
				   const struct bbdd_sockaddr *bsa,
				   struct bbdd_mon *mon,
				   char **error);
void bbdd_ssk_close_c(struct bbdd_ssk_c *ssc);
int bbdd_ssk_c_nq(struct bbdd_ssk_c *ssc, const char *buf, size_t len,
		  char **error);
struct bbdd_ssk_peer *bbdd_ssk_c_peer(struct bbdd_ssk_c *ssc);

int bbdd_ssk_peer_nq(struct bbdd_ssk_peer *peer, const char *buf, size_t len,
		     char **error);
int bbdd_ssk_peer_fd(struct bbdd_ssk_peer *peer);
void bbdd_ssk_peer_mark_done(struct bbdd_ssk_peer *peer);
void bbdd_ssk_peer_disable_debug(struct bbdd_ssk_peer *peer);

/* Synchronously destroy a peer: drain TX best-effort, fire done_cbs in
 * registration order, free cbs, close fd, free the peer. Safe to call
 * from outside an event handler. */
void bbdd_ssk_peer_destroy(struct bbdd_ssk_peer *peer);

struct bbdd_ssk_cbs *
bbdd_ssk_peer_add_cbs(struct bbdd_ssk_peer *peer,
		      int (*rx_cb)(struct bbdd_ssk_peer *peer, const char *buf,
				   size_t len, void *data, char **error),
		      void (*done_cb)(struct bbdd_ssk_peer *peer, void *data),
		      void *data, char **error);

void bbdd_ssk_peer_del_cbs(struct bbdd_ssk_peer *peer,
			   struct bbdd_ssk_cbs *cbs);
