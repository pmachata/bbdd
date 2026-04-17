/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

/* bfddp_packet.h */
struct bfddp_message;

/* bbdd-poll.c */
struct bbdd_poll_ctx;

/* bbdd-bfdd.c */
struct bbdd_bfdd;

struct bbdd_bfdd_cbs {
	void *conn_cb_data;
	void (*connected_cb)(struct bbdd_bfdd *, void *);
	void (*connect_failed_cb)(struct bbdd_bfdd *, char **, void *);
	void (*connect_free_cb)(void *);

	void *sock_cb_data;
	void (*sockerr_cb)(struct bbdd_bfdd *, char **, void *);
	int (*message_cb)(struct bbdd_bfdd *, struct bfddp_message *,
			  void *, char **);
	void (*sock_free_cb)(void *);
};

struct bbdd_bfdd *bbdd_bfdd_open(const char *path,
				 struct bbdd_poll_ctx *pctx,
				 const struct bbdd_bfdd_cbs *cbs,
				 char **error);
void bbdd_bfdd_close(struct bbdd_bfdd *bfdd);
