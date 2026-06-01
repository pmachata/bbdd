/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* bbdd.c */

extern struct bbdd_env {
	const char *sockdir;
	int verbosity;
	bool show_json;
	bool numeric;
	bool timestamp;
	bool mon_eager;
} bbdd_env;

#define bbdd_poison (void *) (uintptr_t) 0xbbdd'dead;
