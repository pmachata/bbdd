// SPDX-License-Identifier: GPL-2.0
#include "bbdd-poll.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include <uthash.h>

#include "bbdd.h"
#include "bbdd-err.h"
#include "bbdd-mon.h"
#include "bbdd-util.h"

struct bbdd_poll_cb {
	int fd;
	short events;
	void (*fn)(struct bbdd_poll_ctx *, short, void *);
	void *data;

	UT_hash_handle hh; /* Keyed by fd. */
};

struct bbdd_poll_ctx {
	int epoll_fd;
	struct bbdd_poll_cb *cbs; /* uthash table of registered fds. */
	struct bbdd_mon *mon;
	bool should_quit;
	int sig_fd;
};

void bbdd_poll_request_quit(struct bbdd_poll_ctx *pctx)
{
	bbdd_mon_send_debug(pctx->mon, "requested stop");
	pctx->should_quit = true;
}

struct bbdd_poll_ctx *bbdd_poll_init(struct bbdd_mon *mon, char **error)
{
	struct bbdd_poll_ctx *pctx;
	int epoll_fd;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		bbdd_err_fmt(error, "Failed to create epoll instance: %m");
		return NULL;
	}

	pctx = malloc(sizeof(*pctx));
	if (pctx == NULL) {
		bbdd_err_fmt(error, "Failed to allocate poll context: %m");
		close(epoll_fd);
		return NULL;
	}
	*pctx = (struct bbdd_poll_ctx){
		.epoll_fd = epoll_fd,
		.mon = mon,
		.sig_fd = -1,
	};
	return pctx;
}

void bbdd_poll_fini(struct bbdd_poll_ctx *pctx)
{
	struct bbdd_poll_cb *cb;
	struct bbdd_poll_cb *tmp;

	HASH_ITER(hh, pctx->cbs, cb, tmp) {
		HASH_DEL(pctx->cbs, cb);
		free(cb);
	}
	close(pctx->epoll_fd);
	free(pctx);
}

static int __bbdd_poll_set_fd(struct bbdd_poll_ctx *pctx,
			      int fd, short events,
			      void (*fn)(struct bbdd_poll_ctx *, short, void *),
			      void *data, char **error)
{
	struct epoll_event ev;
	struct bbdd_poll_cb *cb;
	int op;
	int rc;

	assert(fd >= 0);

	HASH_FIND_INT(pctx->cbs, &fd, cb);
	if (cb == NULL) {
		cb = malloc(sizeof(*cb));
		if (cb == NULL) {
			bbdd_err_from_errno(error);
			return -1;
		}
		*cb = (struct bbdd_poll_cb) { .fd = fd };
		op = EPOLL_CTL_ADD;
	} else {
		op = EPOLL_CTL_MOD;
	}

	cb->events = events;
	cb->fn = fn;
	cb->data = data;

	ev = (struct epoll_event) {
		.events = (uint32_t) events,
		.data.ptr = cb,
	};
	rc = epoll_ctl(pctx->epoll_fd, op, fd, &ev);
	if (rc < 0) {
		bbdd_err_from_errno(error);
		goto free_cb;
	}

	if (op == EPOLL_CTL_ADD)
		HASH_ADD_INT(pctx->cbs, fd, cb);

	return 0;

 free_cb:
	if (op == EPOLL_CTL_ADD)
		free(cb);
	return -1;
}

int bbdd_poll_set_fd(struct bbdd_poll_ctx *pctx,
		     int fd, short events,
		     void (*fn)(struct bbdd_poll_ctx *, short, void *),
		     void *data, char **error)
{
	int rc;

	rc = __bbdd_poll_set_fd(pctx, fd, events, fn, data, error);
	if (rc != 0)
		bbdd_err_app(error, "Failed to register socket for events");
	return rc;
}

int bbdd_poll_unset_fd(struct bbdd_poll_ctx *pctx, int fd)
{
	struct bbdd_poll_cb *cb;

	HASH_FIND_INT(pctx->cbs, &fd, cb);
	if (cb == NULL)
		return -ESRCH;

	epoll_ctl(pctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);

	HASH_DEL(pctx->cbs, cb);
	free(cb);
	return 0;
}

static void bbdd_poll_sig_cb(struct bbdd_poll_ctx *pctx, short, void *)
{
	struct signalfd_siginfo info;
	sigset_t mask;

	read(pctx->sig_fd, &info, sizeof(info));

	/* Graceful shutdown on first signal. Restore the default disposition
	 * and unblock so that a subsequent signal (e.g. a repeated Ctrl-C)
	 * terminates the process immediately. */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	bbdd_poll_request_quit(pctx);
}

int bbdd_poll_set_signals(struct bbdd_poll_ctx *pctx, char **error)
{
	sigset_t mask;
	int sig_fd;
	int err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sig_fd < 0) {
		bbdd_err_from_errno(error);
		goto err;
	}

	err = __bbdd_poll_set_fd(pctx, sig_fd, POLLIN,
				 bbdd_poll_sig_cb, NULL, error);
	if (err != 0)
		goto close_sig_fd;

	pctx->sig_fd = sig_fd;
	return 0;

close_sig_fd:
	close(sig_fd);
err:
	bbdd_err_app(error, "Failed to set up signal handling");
	return err;
}

void bbdd_poll_unset_signals(struct bbdd_poll_ctx *pctx)
{
	assert(pctx->sig_fd >= 0);
	bbdd_poll_unset_fd(pctx, pctx->sig_fd);
	close(pctx->sig_fd);
	pctx->sig_fd = -1;
}

int bbdd_poll_loop(struct bbdd_poll_ctx *pctx, char **error)
{
	struct epoll_event events[64];
	int err = 0;

	bbdd_mon_send_debug(pctx->mon, "ready");

	while (!pctx->should_quit) {
		int nfds;

		nfds = epoll_wait(pctx->epoll_fd, events,
				  ARRAY_SIZE(events), -1);
		if (nfds < 0 && errno != EINTR) {
			bbdd_err_fmt(error, "Failed to epoll_wait: %m");
			err = nfds;
			goto out;
		}
		for (int i = 0; i < nfds; i++) {
			struct bbdd_poll_cb *cb = events[i].data.ptr;
			short revents = (short) events[i].events;

			if (revents & cb->events) {
				cb->fn(pctx, revents, cb->data);
			} else if (revents & (EPOLLERR | EPOLLHUP)) {
				bbdd_err_fmt(error, "Problem on fd %d: %m",
					     cb->fd);
				err = -1;
				goto out;
			}
		}
	}

out:
	return err;
}
