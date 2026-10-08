/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdint.h>

#include "bbdd-mon.i"
#include "bbdd-poll.i"

struct bbdd_timers *bbdd_timers_init(struct bbdd_poll_ctx *pctx,
				     struct bbdd_mon *mon, char **error);
void bbdd_timers_fini(struct bbdd_timers *timers);

/* Schedule fn(data, error) to run once, delay_us from now. */
struct bbdd_timer *bbdd_timer_set(struct bbdd_timers *timers,
				  uint64_t delay_us,
				  int (*fn)(void *data, char **error),
				  void *data, char **error);

void bbdd_timer_cancel(struct bbdd_timer *timer);
