/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdarg.h>
#include <json-c/json_object.h>

#include "bbdd-mon.i"
#include "bbdd-sock.i"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define bbdd_poison (void *) (uintptr_t) 0xbbdd'dead;

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

void bbdd_util_jrpc_respond_echo(struct bbdd_sock *peer,
				 struct json_object *id,
				 uint64_t ts, uint64_t reply_ts);

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
int bbdd_util_parse_time_us(const char *str, uint32_t *ret, char **error);

bool bbdd_util_startswith(const char *haystack, const char *needle,
			  const char **rest);

struct bbdd_util_ssk_json_tkn {
	struct bbdd_ssk_peer *peer;
	struct json_tokener *tok;

	int (*obj_cb)(struct bbdd_util_ssk_json_tkn *tkn,
		      struct json_object *obj, void *data, char **error);
	void *data;
};

struct bbdd_util_ssk_json_tkn *
bbdd_util_ssk_json_tkn_create(int (*obj_cb)(struct bbdd_util_ssk_json_tkn *tkn,
					    struct json_object *obj,
					    void *data, char **error),
			      void *data, char **error);
void bbdd_util_ssk_json_tkn_destroy(struct bbdd_util_ssk_json_tkn *tkn);

int bbdd_util_ssk_json_tkn_rx_cb(struct bbdd_ssk_peer *peer,
				 const char *buf, size_t len,
				 void *data, char **error);
void bbdd_util_ssk_json_tkn_done_cb(struct bbdd_ssk_peer *peer,
				    void *data);
