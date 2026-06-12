/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <json-c/json_object.h>
#include "bbdd-sock.h"
#include "bbdd-poll.i"

struct bbdd_ssk_peer;

struct bbdd_ssk_cbs {
	int (*rx_cb)(struct bbdd_ssk_peer *peer, const char *buf, size_t len,
		     void *data, char **error);
	void (*done_cb)(struct bbdd_ssk_peer *peer, void *data);
	void *data;

	struct bbdd_ssk_cbs *next;
	struct bbdd_ssk_cbs *prev;
};

struct bbdd_ssk_b {
	struct bbdd_ssk_peer *peers;	/* DList. */
	struct bbdd_poll_ctx *pctx;
};

struct bbdd_ssk_d {
	struct bbdd_ssk_b base;
	struct bbdd_sock sock;
	struct bbdd_ssk_cbs cb;
};

struct bbdd_ssk_c {
	struct bbdd_ssk_b base;
};

int bbdd_ssk_open_d(struct bbdd_ssk_d *ssd, struct bbdd_poll_ctx *pctx,
		    const struct bbdd_sockaddr *bsa, char **error);
void bbdd_ssk_close_d(struct bbdd_ssk_d *ssd);
int bbdd_ssk_d_accept(struct bbdd_ssk_d *ssd, struct bbdd_ssk_cbs cbs,
		      char **error);
int bbdd_ssk_d_fd(struct bbdd_ssk_d *ssd);

int bbdd_ssk_open_c(struct bbdd_ssk_c *ssc, struct bbdd_poll_ctx *pctx,
		    const struct bbdd_sockaddr *bsa,
		    struct bbdd_ssk_cbs cbs, char **error);
void bbdd_ssk_close_c(struct bbdd_ssk_c *ssc);
int bbdd_ssk_c_nq(struct bbdd_ssk_c *ssc, const char *buf, size_t len,
		  char **error);

int bbdd_ssk_peer_nq(struct bbdd_ssk_peer *peer, const char *buf, size_t len,
		     char **error);
int bbdd_ssk_peer_fd(struct bbdd_ssk_peer *peer);
void bbdd_ssk_peer_mark_done(struct bbdd_ssk_peer *peer);
struct bbdd_ssk_cbs *bbdd_ssk_peer_add_cbs(struct bbdd_ssk_peer *peer,
					   struct bbdd_ssk_cbs cbs_template,
					   char **error);
void bbdd_ssk_peer_del_cbs(struct bbdd_ssk_peer *peer,
			   struct bbdd_ssk_cbs *cbs);
