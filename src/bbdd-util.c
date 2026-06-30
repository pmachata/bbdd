// SPDX-License-Identifier: GPL-2.0
#include "bbdd-util.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <json-c/json_tokener.h>

#include "bbdd-be.h"
#include "bbdd-err.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-sb.h"
#include "bbdd-ssk.h"
#include "bfddp_packet.h"

int bbdd_util_jrpc_send_keep(struct bbdd_ssk_peer *peer,
			     struct json_object *obj,
			     char **error)
{
	const char *str;

	str = json_object_to_json_string(obj);
	if (str == NULL) {
		bbdd_err_fmt(error, "Failed to serialize JSON object");
		return -1;
	}

	return bbdd_ssk_peer_nq(peer, str, strlen(str), error);
}

int bbdd_util_jrpc_send_done(struct bbdd_ssk_peer *peer,
			     struct json_object *obj,
			     char **error)
{
	bbdd_ssk_peer_mark_done(peer);
	return bbdd_util_jrpc_send_keep(peer, obj, error);
}

void bbdd_util_jrpc_respond(struct bbdd_ssk_peer *peer, struct json_object **obj)
{
	char *error;
	int rc;

	/* Note: *obj is allowed to be NULL. It is better to send an invalid
	 * error response than none at all. */

	rc = bbdd_util_jrpc_send_done(peer, *obj, &error);
	if (rc != 0)
		bbdd_err_print(&error, "Failed to send response");

	json_object_put(*obj);
	*obj = NULL;
}

void bbdd_util_jrpc_respond_inv_params(struct bbdd_ssk_peer *peer,
				       struct json_object *id,
				       const char *msg)
{
	struct json_object *obj = bbdd_jrpc_new_error_inv_params(id, msg);

	bbdd_util_jrpc_respond(peer, &obj);
}


void bbdd_util_jrpc_respond_inv_params_err(struct bbdd_ssk_peer *peer,
					   struct json_object *id,
					   char **data)
{
	bbdd_util_jrpc_respond_inv_params(peer, id, *data);
	free(*data);
	*data = NULL;
}

void bbdd_util_jrpc_respond_interr(struct bbdd_ssk_peer *peer,
				   struct json_object *id,
				   const char *msg)
{
	struct json_object *obj = bbdd_jrpc_new_error_int_error(id, msg);

	bbdd_util_jrpc_respond(peer, &obj);
}

void bbdd_util_jrpc_respond_interr_err(struct bbdd_ssk_peer *peer,
				       struct json_object *id,
				       char **data)
{
	bbdd_util_jrpc_respond_interr(peer, id, *data);
	free(*data);
	*data = NULL;
}

__attribute__((format(printf, 3, 4)))
void bbdd_util_jrpc_respond_interr_fmt(struct bbdd_ssk_peer *peer,
				       struct json_object *id,
				       const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (rc >= 0)
		return bbdd_util_jrpc_respond_interr_err(peer, id, &buf);
	else
		return bbdd_util_jrpc_respond_interr(peer, id, fmt);
}

void bbdd_util_jrpc_respond_memerr(struct bbdd_ssk_peer *peer,
				   struct json_object *id)
{
	bbdd_util_jrpc_respond_interr(peer, id, "Memory allocation issue");
}

static void __bbdd_util_jrpc_respond_empty(struct bbdd_ssk_peer *peer,
					   struct json_object *id,
					   bool keep_open)
{
	struct json_object *obj;
	char *error;
	int rc;

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (json_object_object_add(obj, "result", NULL))
		goto put_obj;

	if (keep_open)
		rc = bbdd_util_jrpc_send_keep(peer, obj, &error);
	else
		rc = bbdd_util_jrpc_send_done(peer, obj, &error);

	if (rc != 0)
		bbdd_err_print(&error, "Failed to send empty response");

	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	bbdd_util_jrpc_respond_memerr(peer, id);
}

void bbdd_util_jrpc_respond_empty(struct bbdd_ssk_peer *peer,
				  struct json_object *id)
{
	__bbdd_util_jrpc_respond_empty(peer, id, false);
}

void bbdd_util_jrpc_respond_empty_keep(struct bbdd_ssk_peer *peer,
				       struct json_object *id)
{
	__bbdd_util_jrpc_respond_empty(peer, id, true);
}

void bbdd_util_jrpc_respond_method_nf(struct bbdd_ssk_peer *peer,
				      struct json_object *id,
				      const char *method)
{
	struct json_object *obj = bbdd_jrpc_new_error_method_nf(id, method);

	bbdd_util_jrpc_respond(peer, &obj);
}

void bbdd_util_jrpc_respond_echo(struct bbdd_ssk_peer *peer,
				 struct json_object *id,
				 uint64_t ts, uint64_t reply_ts)
{
	struct json_object *result;
	struct json_object *resp;
	char *error;
	int rc;

	resp = bbdd_jrpc_new_object(id);
	if (resp == NULL)
		goto err_memerr;

	result = json_object_new_object();
	if (result == NULL)
		goto put_resp;

	if (bbdd_jrpc_append_uint64(result, "ts", ts) ||
	    bbdd_jrpc_append_uint64(result, "reply_ts", reply_ts))
		goto put_result;

	rc = bbdd_jrpc_append_obj(resp, "result", &result);
	if (rc != 0)
		goto put_result;

	rc = bbdd_util_jrpc_send_done(peer, resp, &error);
	if (rc != 0)
		// xxx monitor
		bbdd_err_print(&error, "Failed to send echo response");

	json_object_put(resp);
	return;

put_result:
	json_object_put(result);
put_resp:
	json_object_put(resp);
err_memerr:
	bbdd_util_jrpc_respond_memerr(peer, id);
}

struct json_object *bbdd_util_jrpc_addr_obj(const char *addr, int af)
{
	struct json_object *obj;

	obj = json_object_new_object();
	if (obj == NULL)
		return NULL;

	if (bbdd_jrpc_append_str(obj, "addr", addr) ||
	    bbdd_jrpc_append_str(obj, "family", bbdd_sock_af_to_str(af)))
		goto put_obj;

	return obj;

put_obj:
	json_object_put(obj);
	return NULL;
}

static void bbdd_util_ctl_mon_send(struct bbdd_mon *mon,
				   enum bbdd_mon_topic topic,
				   struct json_object *request_obj)
{
	struct bbdd_mon_message mon_msg = {
		.method = "jrpc:request",
	};
	int rc;

	mon_msg.params = json_object_new_object();
	if (mon_msg.params == NULL)
		return;

	rc = json_object_object_add(mon_msg.params, "message",
				    request_obj);
	if (rc != 0)
		goto put_params;
	json_object_get(request_obj);

	bbdd_mon_send(mon, &mon_msg, topic);
	return;

put_params:
	json_object_put(mon_msg.params);
}

void bbdd_util_ssk_recv_obj(struct json_object *request_obj,
			    struct bbdd_ssk_peer *peer,
			    struct bbdd_mon *mon,
			    void (*cb)(struct bbdd_ssk_peer *peer,
				       const char *method,
				       struct json_object *params_obj,
				       struct json_object *id,
				       void *data),
			    void *data)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_jrpc;
	struct json_object *params;
	struct json_object *obj;
	struct json_object *id;
	const char *method;
	char *error;
	int err;

	if (bbdd_mon_topic_active(mon, topic))
		bbdd_util_ctl_mon_send(mon, topic, request_obj);

	/* request_obj is JSON `null'. */
	if (request_obj == NULL) {
		obj = bbdd_jrpc_new_error_inv_request("null");
		bbdd_util_jrpc_respond(peer, &obj);
		return;
	}

	err = bbdd_jrpc_dissect_request(request_obj, &id, &method, &params,
					&error);
	if (err) {
		obj = bbdd_jrpc_new_error_inv_request(error);
		bbdd_util_jrpc_respond(peer, &obj);
		free(error);
		return;
	}

	cb(peer, method, params, id, data);
}

uint64_t bbdd_util_now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t) tv.tv_sec) * 1000000 + tv.tv_usec;
}

int bbdd_util_parse_time_us(const char *str, uint32_t *ret, char **error)
{
	unsigned long long val;
	uint32_t mult;
	char *end;

	val = strtoull(str, &end, 0);
	if (end == str) {
		bbdd_err_fmt(error, "not a valid number");
		return -1;
	}
	if (val <= 0 || val > UINT32_MAX)
		goto oob;

	if (strcmp(end, "us") == 0 || *end == '\0') {
		mult = 1;
	} else if (strcmp(end, "ms") == 0) {
		mult = 1000;
	} else if (strcmp(end, "s") == 0) {
		mult = 1000000;
	} else {
		bbdd_err_fmt(error, "unknown unit `%s' (use us, ms, s)", end);
		return -1;
	}

	if (val > UINT32_MAX / mult) {
oob:
		bbdd_err_fmt(error, "value out of bounds (0, uint32_max]");
		return -1;
	}

	*ret = (uint32_t)(val * mult);
	return 0;
}

bool bbdd_util_startswith(const char *haystack, const char *needle,
			  const char **rest)
{
	size_t sz = strlen(needle);

	if (strncmp(haystack, needle, sz) != 0)
		return false;

	*rest = haystack + sz;
	return true;
}

static int bbdd_util_jrpc_tokenize(struct json_tokener *tok,
				   const char **str, size_t *left,
				   struct json_object **ret_obj, char **error)
{
	struct json_object *obj;
	size_t consumed;
	int rc;

	obj = json_tokener_parse_ex(tok, *str, *left);
	consumed = json_tokener_get_parse_end(tok);
	assert(consumed <= *left);
	*left -= consumed;
	*str += consumed;
	*ret_obj = obj;
	if (obj == NULL) {
		rc = json_tokener_get_error(tok);
		if (rc == json_tokener_success) {
			/* A `null' JSON object. */
			return 0;
		}
		if (rc == json_tokener_continue) {
			/* Not enough to form a full JSON object. */
			return 1;
		}

		bbdd_err_fmt(error, "JSON parse error: %s",
			     json_tokener_error_desc(rc));
		return -1;
	}

	json_tokener_reset(tok);
	return 0;
}

struct bbdd_util_ssk_json_tkn *
bbdd_util_ssk_json_tkn_create(int (*obj_cb)(struct bbdd_util_ssk_json_tkn *tkn,
					    struct json_object *obj,
					    void *data, char **error),
			      void *data, char **error)
{
	struct bbdd_util_ssk_json_tkn *tkn;
	struct json_tokener *tok;

	tkn = malloc(sizeof(*tkn));
	if (tkn == NULL) {
		bbdd_err_fmt(error, "dispatch context alloc: %m");
		return NULL;
	}

	tok = json_tokener_new();
	if (tok == NULL) {
		bbdd_err_fmt(error, "json_tokener_new: %m");
		goto free_tkn;
	}

	*tkn = (struct bbdd_util_ssk_json_tkn) {
		.tok = tok,
		.obj_cb = obj_cb,
		.data = data,
	};

	return tkn;

free_tkn:
	free(tkn);
	return NULL;
}

void bbdd_util_ssk_json_tkn_destroy(struct bbdd_util_ssk_json_tkn *tkn)
{
	json_tokener_free(tkn->tok);
	free(tkn);
}

int bbdd_util_ssk_json_tkn_rx_cb(struct bbdd_ssk_peer *peer,
				 const char *buf, size_t len,
				 void *data, char **error)
{
	struct bbdd_util_ssk_json_tkn *tkn = data;
	int rc;

	/* At this point we can backfill the peer. */
	assert(tkn->peer == NULL || tkn->peer == peer);
	tkn->peer = peer;

	while (len > 0) {
		struct json_object *obj;

		rc = bbdd_util_jrpc_tokenize(tkn->tok, &buf, &len, &obj, error);
		if (rc < 0) {
			if (tkn->err_cb == NULL)
				return rc;
			rc = tkn->err_cb(tkn, tkn->data, error);
			if (rc != 0)
				return rc;
			/* Resync: the tokenizer stopped at the offending byte
			 * without consuming it. Skip past it and start a
			 * fresh parse. */
			json_tokener_reset(tkn->tok);
			if (len > 0) {
				buf++;
				len--;
			}
			continue;
		}
		if (rc > 0) {
			/* Continue. */
			assert(len == 0);
			break;
		}

		/* Note: obj == NULL for JSON `null'. */
		rc = tkn->obj_cb(tkn, obj, tkn->data, error);
		json_object_put(obj);
		if (rc != 0)
			return rc;
	}

	return 0;
}

struct bbdd_util_ssk_bfddp_tkn {
	//uint8_t buf[sizeof(struct bfddp_message)];
	struct bbdd_sb sb;
	size_t len;

	int (*obj_cb)(struct bbdd_util_ssk_bfddp_tkn *tkn,
		      const struct bfddp_message *msg, void *data,
		      char **error);
	void *data;
};

struct bbdd_util_ssk_bfddp_tkn *
bbdd_util_ssk_bfddp_tkn_create(int (*obj_cb)(struct bbdd_util_ssk_bfddp_tkn *tkn,
					     const struct bfddp_message *msg,
					     void *data, char **error),
			       void *data, char **error)
{
	struct bbdd_util_ssk_bfddp_tkn *tkn;

	tkn = malloc(sizeof(*tkn));
	if (tkn == NULL) {
		bbdd_err_fmt(error, "bfddp tkn alloc: %m");
		return NULL;
	}

	*tkn = (struct bbdd_util_ssk_bfddp_tkn) {
		.obj_cb = obj_cb,
		.data = data,
	};

	return tkn;
}

void bbdd_util_ssk_bfddp_tkn_destroy(struct bbdd_util_ssk_bfddp_tkn *tkn)
{
	bbdd_sb_fini(&tkn->sb);
	free(tkn);
}

int bbdd_util_ssk_bfddp_tkn_rx_cb(struct bbdd_ssk_peer *,
				  const char *buf, size_t len,
				  void *data, char **error)
{
	struct bbdd_util_ssk_bfddp_tkn *tkn = data;
	int rc;

	rc = bbdd_sb_push_len(&tkn->sb, buf, len, error);
	if (rc != 0)
		return rc;

	while (true) {
		size_t sb_len = bbdd_sb_len(&tkn->sb);
		const struct bfddp_message *msg;
		size_t msg_len;

		if (sb_len < sizeof(msg->header))
			/* We don't even have enough to look at length. */
			return 0;

		msg = bbdd_sb_buf(&tkn->sb);
		msg_len = bbdd_ntoh16(msg->header.length);
		if (sb_len < msg_len)
			/* We don't have the full message yet. */
			return 0;

		rc = tkn->obj_cb(tkn, msg, tkn->data, error);

		/* Discard the message even if the cb failed. */
		bbdd_sb_pull(&tkn->sb, msg_len);

		if (rc != 0)
			return rc;
	}
}
