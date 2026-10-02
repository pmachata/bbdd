// SPDX-License-Identifier: GPL-2.0
#include "bbdd-timer.h"

#include <assert.h>
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

	struct bbdd_timer *prev;
	struct bbdd_timer *next;
};

struct bbdd_timers {
	struct bbdd_poll_ctx *pctx;
	int fd;
	struct bbdd_timer *head; /* DList of timers. */
};

static uint64_t bbdd_timers_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1'000'000'000ULL + (uint64_t) ts.tv_nsec;
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

static int bbdd_timer_cmp(const struct bbdd_timer *a,
			  const struct bbdd_timer *b)
{
	if (a->deadline_ns < b->deadline_ns)
		return -1;
	if (a->deadline_ns > b->deadline_ns)
		return 1;
	return 0;
}

struct bbdd_timer *bbdd_timer_set(struct bbdd_timers *timers,
				  uint64_t delay_us,
				  int (*fn)(void *data, char **error),
				  void *data, char **error)
{
	struct bbdd_timer *timer;
	int rc;

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

	if (timers->head == timer) {
		rc = bbdd_timers_rearm(timers, error);
		if (rc != 0)
			goto delete;
	}

	return timer;

 delete:
	DL_DELETE(timers->head, timer);
	free(timer);
	return NULL;
}

static void __bbdd_timer_cancel(struct bbdd_timer *timer)
{
	struct bbdd_timers *timers = timer->timers;

	DL_DELETE(timers->head, timer);
	free(timer);
}

void bbdd_timer_cancel(struct bbdd_timer *timer)
{
	struct bbdd_timers *timers = timer->timers;
	bool was_earliest = timers->head == timer;
	char *error;
	int rc;

	__bbdd_timer_cancel(timer);

	if (was_earliest) {
		rc = bbdd_timers_rearm(timers, &error);
		if (rc != 0)
			// xxx monitor
			bbdd_err_print(&error, "Failed to rearm timer");
	}
}

static int bbdd_timers_fd_cb(struct bbdd_poll_ctx *, short, void *data,
			     char **error)
{
	struct bbdd_timers *timers = data;
	struct bbdd_timer *failed = NULL;
	struct bbdd_timer *timer;
	struct bbdd_timer *tmp;
	uint64_t expirations;
	uint64_t now_ns;
	int rc = 0;

	/* Drain the timerfd so poll does not fire again. */
	(void) read(timers->fd, &expirations, sizeof(expirations));
	now_ns = bbdd_timers_now_ns();

	/* To allow callbacks destroying their objects, including descheduling
	 * the very timer the callback was invoked for, first just walk the
	 * prefix and invoke the callbacks. */
	DL_FOREACH_SAFE(timers->head, timer, tmp) {
		if (timer->deadline_ns > now_ns)
			break;

		rc = timer->fn(timer->data, error);
		if (rc != 0) {
			failed = timer;
			break;
		}
	}

	/* Now, in second pass, actually deallocate what we invoked. */
	while (timers->head != NULL && timers->head->deadline_ns <= now_ns) {
		struct bbdd_timer *due = timers->head;

		__bbdd_timer_cancel(due);
		if (due == failed) {
			failed = NULL;
			break;
		}
	}

	/* We only set `failed' if a timer callback returned an error. A
	 * function that returned error should not have modified its
	 * environment, so we must have seen the node in cleanup pass. */
	assert(failed == NULL);

	if (rc != 0)
		return -1;

	return bbdd_timers_rearm(timers, error);
}

struct bbdd_timers *bbdd_timers_init(struct bbdd_poll_ctx *pctx, char **error)
{
	struct bbdd_timers *timers;
	int fd;
	int rc;

	timers = malloc(sizeof(*timers));
	if (timers == NULL) {
		bbdd_err_fmt(error, "Failed to allocate timers context: %m");
		return NULL;
	}

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		bbdd_err_fmt(error, "Failed to create timer: %m");
		goto free_timers;
	}

	rc = bbdd_poll_set_fd(pctx, fd, POLLIN, bbdd_timers_fd_cb,
			      timers, error);
	if (rc != 0)
		goto close_fd;

	*timers = (struct bbdd_timers) {
		.pctx = pctx,
		.fd = fd,
	};
	return timers;

close_fd:
	close(fd);
free_timers:
	free(timers);
	return NULL;
}

void bbdd_timers_fini(struct bbdd_timers *timers)
{
	assert(timers->head == NULL);

	bbdd_poll_unset_fd(timers->pctx, timers->fd);
	close(timers->fd);
	free(timers);
}
