/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdlib.h>

struct bbdd_poll_ctx;

struct bbdd_poll_ctx *bbdd_poll_init(void);
void bbdd_poll_fini(struct bbdd_poll_ctx *ctx);

int bbdd_poll_push_fd(struct bbdd_poll_ctx *ctx,
		      int fd, short events,
		      int (*fn)(struct bbdd_poll_ctx *, short, void *, char **),
		      void *data, char **error);
void bbdd_poll_request_quit(struct bbdd_poll_ctx *ctx);

int bbdd_poll_loop(struct bbdd_poll_ctx *ctx, char **error);
