// SPDX-License-Identifier: GPL-2.0
#include "bbdd-timer.h"

#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <utlist.h>

#include "bbdd-err.h"
#include "bbdd-poll.h"

struct bbdd_timer {
	struct bbdd_timers *timers;
	uint64_t deadline_ns; /* CLOCK_MONOTONIC, absolute */
	int (*fn)(void *data, char **error);
	void *data;

	/* Set right before fn() runs. fn() commonly tears down the object
	 * that owns this handle, which as often as not calls
	 * bbdd_timer_cancel() on it unconditionally, not knowing whether it
	 * is cancelling a still-pending timer or reacting to this very
	 * firing. This flag makes the latter a safe no-op: the handle is
	 * already unlinked, and the dispatcher frees it once fn() returns. */
	bool firing;

	/* DList, timers->head sorted by deadline_ns ascending. */
	struct bbdd_timer *prev;
	struct bbdd_timer *next;
};

struct bbdd_timers {
	struct bbdd_poll_ctx *pctx;
	int fd;
	struct bbdd_timer *head;
};

static uint64_t bbdd_timers_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1'000'000'000ULL + (uint64_t) ts.tv_nsec;
}

static int bbdd_timer_cmp(const struct bbdd_timer *a,
			  const struct bbdd_timer *b)
{
	if (a->deadline_ns < b->deadline_ns)
		return -1;
	if (a->deadline_ns > b->deadline_ns)
		return 1;
	return 0;
}

/* Arms the shared timerfd for the current earliest pending deadline, or
 * disarms it when there is none. */
static int bbdd_timers_rearm(struct bbdd_timers *timers, char **error)
{
	struct itimerspec its = {};

	if (timers->head != NULL) {
		its.it_value.tv_sec = timers->head->deadline_ns / 1'000'000'000ULL;
		its.it_value.tv_nsec = timers->head->deadline_ns % 1'000'000'000ULL;
	}

	if (timerfd_settime(timers->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
		bbdd_err_fmt(error, "Failed to arm timer: %m");
		return -1;
	}
	return 0;
}

static int bbdd_timers_fd_cb(struct bbdd_poll_ctx *, short, void *data,
			     char **error)
{
	struct bbdd_timers *timers = data;
	uint64_t expirations;
	uint64_t now_ns;

	/* Drain the timerfd so poll does not fire again for the same
	 * expiration count. */
	(void) read(timers->fd, &expirations, sizeof(expirations));

	/* Take `now' once: draining everything due as of when we started,
	 * rather than re-checking the clock after every callback, bounds how
	 * long a single invocation can run for when a lot of timers are due
	 * at once. Anything that becomes due while we're draining gets
	 * picked up on the next, immediate poll() wakeup instead, since
	 * arming an already-past absolute deadline fires right away. */
	now_ns = bbdd_timers_now_ns();
	while (timers->head != NULL && timers->head->deadline_ns <= now_ns) {
		struct bbdd_timer *timer = timers->head;
		int (*fn)(void *, char **) = timer->fn;
		void *fn_data = timer->data;
		int rc;

		DL_DELETE(timers->head, timer);
		timer->firing = true;

		rc = fn(fn_data, error);
		free(timer);
		if (rc != 0)
			return -1;
	}

	return bbdd_timers_rearm(timers, error);
}

struct bbdd_timers *bbdd_timers_init(struct bbdd_poll_ctx *pctx, char **error)
{
	struct bbdd_timers *timers;

	timers = malloc(sizeof(*timers));
	if (timers == NULL) {
		bbdd_err_fmt(error, "Failed to allocate timers context: %m");
		return NULL;
	}

	*timers = (struct bbdd_timers) {
		.pctx = pctx,
		.fd = -1,
	};

	timers->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timers->fd < 0) {
		bbdd_err_fmt(error, "Failed to create timer: %m");
		goto free_timers;
	}

	if (bbdd_poll_set_fd(pctx, timers->fd, POLLIN, bbdd_timers_fd_cb,
			     timers, error) != 0)
		goto close_fd;

	return timers;

close_fd:
	close(timers->fd);
free_timers:
	free(timers);
	return NULL;
}

void bbdd_timers_fini(struct bbdd_timers *timers)
{
	struct bbdd_timer *timer, *tmp;

	/* Anything still pending here belongs to an object that should have
	 * cancelled it during its own teardown. Just free it without running
	 * its callback, same as closing a timerfd that never fired. */
	DL_FOREACH_SAFE(timers->head, timer, tmp) {
		DL_DELETE(timers->head, timer);
		free(timer);
	}

	bbdd_poll_unset_fd(timers->pctx, timers->fd);
	close(timers->fd);
	free(timers);
}

struct bbdd_timer *bbdd_timer_set(struct bbdd_timers *timers,
				  uint64_t delay_us,
				  int (*fn)(void *data, char **error),
				  void *data, char **error)
{
	struct bbdd_timer *timer;

	timer = malloc(sizeof(*timer));
	if (timer == NULL) {
		bbdd_err_fmt(error, "Failed to allocate timer: %m");
		return NULL;
	}

	*timer = (struct bbdd_timer) {
		.timers = timers,
		.deadline_ns = bbdd_timers_now_ns() + delay_us * 1000,
		.fn = fn,
		.data = data,
	};

	DL_INSERT_INORDER(timers->head, timer, bbdd_timer_cmp);

	if (timers->head == timer && bbdd_timers_rearm(timers, error) != 0) {
		DL_DELETE(timers->head, timer);
		free(timer);
		return NULL;
	}

	return timer;
}

void bbdd_timer_cancel(struct bbdd_timer *timer)
{
	struct bbdd_timers *timers;
	bool was_earliest;
	char *error;

	if (timer == NULL || timer->firing)
		return;

	timers = timer->timers;
	was_earliest = (timers->head == timer);

	DL_DELETE(timers->head, timer);
	free(timer);

	if (was_earliest && bbdd_timers_rearm(timers, &error) != 0)
		bbdd_err_print(&error, "Failed to rearm timer");
}
