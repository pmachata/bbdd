// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-poll.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

#include "bbdd.h"
#include "bbdd-util.h"

struct bbdd_poll_cb {
	int (*fn)(struct bbdd_poll_ctx *, short, void *, char **);
	void *data;
};

struct bbdd_poll_ctx {
	struct pollfd *fds;
	struct bbdd_poll_cb *cbs;
	size_t num;
	bool should_quit;
};

void bbdd_poll_request_quit(struct bbdd_poll_ctx *ctx)
{
	if (bbdd_env.verbosity > 0)
		fprintf(stderr, "requested stop\n");
	ctx->should_quit = true;
}

struct bbdd_poll_ctx *bbdd_poll_init(void)
{
	struct bbdd_poll_ctx *pctx;

	pctx = malloc(sizeof(*pctx));
	if (pctx == NULL)
		return NULL;
	*pctx = (struct bbdd_poll_ctx){};
	return pctx;
}

void bbdd_poll_fini(struct bbdd_poll_ctx *pctx)
{
	free(pctx->fds);
	free(pctx->cbs);
	free(pctx);
}

static ssize_t bbdd_poll_find_slot(struct bbdd_poll_ctx *pctx, int fd)
{
	ssize_t empty = -1;

	for (size_t i = 0; i < pctx->num; i++)
		if (pctx->fds[i].fd < 0)
			empty = i;
		else if (pctx->fds[i].fd == fd)
			return (ssize_t) i;
	return empty;
}

static ssize_t __bbdd_poll_reserve(struct bbdd_poll_ctx *pctx, int fd,
				   char **error)
{
	size_t new_n = pctx->num + 1;
	struct bbdd_poll_cb *new_cbs;
	struct pollfd *new_fds;
	ssize_t ix;

	ix = bbdd_poll_find_slot(pctx, fd);
	if (ix >= 0)
		return ix;

	new_fds = realloc(pctx->fds, sizeof(*new_fds) * new_n);
	if (new_fds == NULL)
		goto error;

	new_cbs = realloc(pctx->cbs, sizeof(*new_cbs) * new_n);
	if (new_cbs == NULL)
		goto new_fds;

	new_fds[pctx->num] = (struct pollfd) {};
	new_cbs[pctx->num] = (struct bbdd_poll_cb) {};
	pctx->fds = new_fds;
	pctx->cbs = new_cbs;
	return pctx->num++;

new_fds:
	free(new_fds);
error:
	bbdd_util_fmterr(error, "%m");
	return -1;
}

int bbdd_poll_set_fd(struct bbdd_poll_ctx *pctx,
		     int fd, short events,
		     int (*fn)(struct bbdd_poll_ctx *, short, void *, char **),
		     void *data, char **error)
{
	ssize_t ix;

	assert(fd >= 0);

	ix = __bbdd_poll_reserve(pctx, fd, error);
	if (ix < 0)
		return -1;

	pctx->fds[ix] = (struct pollfd) {
		.fd = fd,
		.events = events,
	};
	pctx->cbs[ix] = (struct bbdd_poll_cb) {
		.fn = fn,
		.data = data,
	};
	return 0;

}

int bbdd_poll_unset_fd(struct bbdd_poll_ctx *pctx, int fd)
{
	for (size_t i = 0; i < pctx->num; i++)
		if (pctx->fds[i].fd == fd) {
			pctx->fds[i] = (struct pollfd) {
				.fd = -1,
			};
			pctx->cbs[i] = (struct bbdd_poll_cb) {};
			return 0;
		}
	return -ESRCH;
}

int bbdd_poll_loop(struct bbdd_poll_ctx *pctx, char **error)
{
	int err = 0;

	while (!pctx->should_quit) {
		int nfds;

		nfds = poll(pctx->fds, pctx->num, -1);
		if (nfds < 0 && errno != EINTR) {
			bbdd_util_fmterr(error, "Failed to poll: %m");
			err = nfds;
			goto out;
		}
		if (nfds == 0)
			continue;
		for (size_t i = 0; i < pctx->num; i++) {
			struct pollfd *pollfd = &pctx->fds[i];

			if (pollfd->revents & (POLLERR | POLLHUP |
					       POLLNVAL)) {
				bbdd_util_fmterr(error, "Problem on pollfd #%zd: %m",
						 i);
				err = -1;
				goto out;
			}
			if (pollfd->revents & pollfd->events) {
				struct bbdd_poll_cb *cb = &pctx->cbs[i];

				err = cb->fn(pctx, pollfd->revents, cb->data,
					     error);
				if (err)
					goto out;
			}
		}
	}

out:
	return err;
}
