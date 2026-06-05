/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdarg.h>
#include <json-c/json_object.h>

#include "bbdd-mon.i"
#include "bbdd-sock.i"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

/* JRPC helpers. */

int bbdd_util_jrpc_send(struct bbdd_sock *sock, struct json_object *obj,
			char **error);

void bbdd_util_jrpc_respond(struct bbdd_sock *ctl, struct json_object *obj);

void bbdd_util_jrpc_respond_inv_params(struct bbdd_sock *ctl,
				       struct json_object *id,
				       const char *msg);

void bbdd_util_jrpc_respond_inv_params_err(struct bbdd_sock *ctl,
					   struct json_object *id,
					   char **data);

void bbdd_util_jrpc_respond_interr(struct bbdd_sock *peer,
				   struct json_object *id,
				   const char *msg);

void bbdd_util_jrpc_respond_interr_err(struct bbdd_sock *peer,
				       struct json_object *id,
				       char **data);

__attribute__((format(printf, 3, 4)))
void bbdd_util_jrpc_respond_interr_fmt(struct bbdd_sock *peer,
				       struct json_object *id,
				       const char *fmt, ...);

void bbdd_util_jrpc_respond_memerr(struct bbdd_sock *peer,
				   struct json_object *id);

void bbdd_util_jrpc_respond_empty(struct bbdd_sock *peer,
				  struct json_object *id);

void bbdd_jrpc_respond_echo(struct bbdd_sock *peer,
			    struct json_object *id,
			    uint64_t bfdd_time, uint64_t dp_time);

struct json_object *bbdd_util_jrpc_addr_obj(const char *addr, int af);

void bbdd_util_ctl_activity(struct bbdd_sock *ctl,
			    struct bbdd_mon *mon,
			    void (*cb)(struct bbdd_sock *peer,
				       const char *method,
				       struct json_object *params_obj,
				       struct json_object *id,
				       void *data),
			    void *data);

uint64_t bbdd_util_now(void);
