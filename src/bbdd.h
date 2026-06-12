/* SPDX-License-Identifier: GPL-2.0 */
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

struct bbdd_ec {
	int __ec;
};

extern const struct bbdd_ec bbdd_ec_success;
extern const struct bbdd_ec bbdd_ec_failure;

bool bbdd_ec_is_success(struct bbdd_ec ec);
