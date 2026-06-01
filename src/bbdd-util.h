/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdarg.h>
#include <json-c/json_object.h>

#include "bbdd-mon.i"
#include "bbdd-sock.i"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

int bbdd_util_vfmterr(char **strp, const char *fmt, va_list ap);

/* Format an error into *strp. *strp is initialized to NULL on out of
 * memory conditions, so it is in a well-defined state after the call. The
 * incoming value of *strp can be uninitialized. */
__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...);

/* Given a valid string in *strp, form a new string, free *strp, and put
 * the new string there. fmt can therefore reference *strp itself. Leaves
 * *strp intact on out of memory conditions. */
__attribute__((format(printf, 2, 3)))
int bbdd_util_wraperr(char **strp, const char *fmt, ...);

/* Formats the given message. Then when *error is non-NULL, it appends a
 * ": $error" afterwards. Puts the resulting pointer back to *error. */
__attribute__((format(printf, 2, 3)))
int bbdd_util_appenderr(char **error, const char *fmt, ...);

/* Prints the given message. Then when *error is non-NULL, it appends a
 * ": $error" afterwards. Puts the resulting pointer back to *error. */
__attribute__((format(printf, 2, 3)))
void bbdd_util_printerr(char **error, const char *fmt, ...);

int bbdd_util_pickerr(int rc1, char **error1, int rc2, char **error2);
void bbdd_util_xferr(char **error, char **src);

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
