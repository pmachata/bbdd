/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <json-c/json_object.h>

#include "bbdd-sock.h"

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* bbdd.c */

extern struct bbdd_env {
	const char *sockdir;
	int verbosity;
	bool show_json;
} bbdd_env;

int bbdd_jrpc_send(struct bbdd_sock *sock, struct json_object *obj);

/* c.c */

int bbdd_c_stop(int argc, char **argv);
int bbdd_c_ping(int argc, char **argv);
int bbdd_c_session(int argc, char **argv);

/* d.c */

int bbdd_d_start(int argc, char **argv);
