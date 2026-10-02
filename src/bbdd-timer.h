/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdint.h>

#include "bbdd-poll.i"
#include "bbdd-timer.i"

/* A facility for one-shot timers backed by a single shared timerfd, instead
 * of one timerfd per pending timer. Useful when the number of concurrently
 * pending timers can scale with e.g. the number of sessions, where a
 * timerfd-per-timer approach risks exhausting the process's file
 * descriptors. */

struct bbdd_timers *bbdd_timers_init(struct bbdd_poll_ctx *pctx, char **error);
void bbdd_timers_fini(struct bbdd_timers *timers);

/* Schedules fn(data, error) to run once, no earlier than delay_us
 * microseconds from now. Returns a handle to pass to bbdd_timer_cancel(),
 * or NULL on error. Once fn has run for a given timer, the handle is no
 * longer valid and must not be passed to bbdd_timer_cancel(). */
struct bbdd_timer *bbdd_timer_set(struct bbdd_timers *timers,
				  uint64_t delay_us,
				  int (*fn)(void *data, char **error),
				  void *data, char **error);

/* NULL-safe. */
void bbdd_timer_cancel(struct bbdd_timer *timer);
