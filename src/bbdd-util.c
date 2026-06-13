// SPDX-License-Identifier: GPL-2.0
#include "bbdd-util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <json-c/json_tokener.h>

#include "bbdd.h"
#include "bbdd-err.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-sock.h"

int bbdd_util_jrpc_send(struct bbdd_sock *sock, struct json_object *obj,
			char **error)
{
	const char *str;
	size_t len;
	ssize_t rc;

	str = json_object_to_json_string(obj);
	if (str == NULL) {
		bbdd_err_fmt(error, "Failed to serialize JSON object");
		return -1;
	}

	len = strlen(str);
	rc = sendto(sock->fd, str, len, 0,
		    (struct sockaddr *) &sock->sa, sock->sa.len);
	if (rc < 0) {
		bbdd_err_fmt(error, "sendto: %m");
		return -1;
	}
	if ((size_t)rc != len) {
		bbdd_err_fmt(error, "sendto: Failed to write the full message");
		return -1;
	}
	return 0;
}

void bbdd_util_jrpc_respond(struct bbdd_sock *ctl, struct json_object *obj)
{
	char *error;
	int rc;

	if (obj == NULL)
		return;

	rc = bbdd_util_jrpc_send(ctl, obj, &error);
	if (rc != 0)
		bbdd_err_print(&error, "Failed to send response");

	json_object_put(obj);
}

void bbdd_util_jrpc_respond_inv_params(struct bbdd_sock *ctl,
				       struct json_object *id,
				       const char *msg)
{
	bbdd_util_jrpc_respond(ctl, bbdd_jrpc_new_error_inv_params(id, msg));
}

void bbdd_util_jrpc_respond_inv_params_err(struct bbdd_sock *ctl,
					   struct json_object *id,
					   char **data)
{
	bbdd_util_jrpc_respond_inv_params(ctl, id, *data);
	free(*data);
	*data = NULL;
}

void bbdd_util_jrpc_respond_interr(struct bbdd_sock *peer,
				   struct json_object *id,
				   const char *msg)
{
	bbdd_util_jrpc_respond(peer, bbdd_jrpc_new_error_int_error(id, msg));
}

void bbdd_util_jrpc_respond_interr_err(struct bbdd_sock *peer,
				       struct json_object *id,
				       char **data)
{
	bbdd_util_jrpc_respond_interr(peer, id, *data);
	free(*data);
	*data = NULL;
}

__attribute__((format(printf, 3, 4)))
void bbdd_util_jrpc_respond_interr_fmt(struct bbdd_sock *peer,
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

void bbdd_util_jrpc_respond_memerr(struct bbdd_sock *peer,
				   struct json_object *id)
{
	bbdd_util_jrpc_respond_interr(peer, id, "Memory allocation issue");
}

void bbdd_util_jrpc_respond_empty(struct bbdd_sock *peer,
				  struct json_object *id)
{
	struct json_object *obj;
	char *error;
	int rc;

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (json_object_object_add(obj, "result", NULL))
		goto put_obj;

	rc = bbdd_util_jrpc_send(peer, obj, &error);
	if (rc != 0)
		bbdd_err_print(&error, "Failed to send empty response");

	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	bbdd_util_jrpc_respond_memerr(peer, id);
}

void bbdd_jrpc_respond_echo(struct bbdd_sock *peer,
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

	rc = bbdd_util_jrpc_send(peer, resp, &error);
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
				   const char *request,
				   struct json_object *request_obj)
{
	struct bbdd_mon_message mon_msg = {
		.method = "jrpc:request",
	};
	int rc;

	mon_msg.params = json_object_new_object();
	if (mon_msg.params == NULL)
		return;

	/* If we could parse it, append the parse, fall back to string. */
	if (request_obj != NULL) {
		rc = json_object_object_add(mon_msg.params, "message",
					    request_obj);
		if (rc != 0)
			goto string;
		json_object_get(request_obj);
	} else {
	string:
		rc = bbdd_jrpc_append_str(mon_msg.params, "message", request);
		if (rc != 0) {
			json_object_put(mon_msg.params);
			return;
		}
	}

	bbdd_mon_send(mon, &mon_msg, topic);
}

void bbdd_util_ctl_activity(struct bbdd_sock *ctl,
			    struct bbdd_mon *mon,
			    void (*cb)(struct bbdd_sock *peer,
				       const char *method,
				       struct json_object *params_obj,
				       struct json_object *id,
				       void *data),
			    void *data)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_jrpc;
	struct json_object *request_obj;
	struct json_object *params;
	struct bbdd_sock peer;
	struct json_object *id;
	char *request = NULL;
	const char *method;
	char *error;
	int err;

	err = bbdd_sock_recv(ctl, &peer, &request, &error);
	if (err < 0) {
		bbdd_err_print(&error, "Failed to receive response");
		return;
	}

	request_obj = json_tokener_parse(request);

	if (bbdd_mon_topic_active(mon, topic))
		bbdd_util_ctl_mon_send(mon, topic, request, request_obj);

	if (request_obj == NULL) {
		bbdd_util_jrpc_respond(&peer,
				       bbdd_jrpc_new_error_inv_request(NULL));
		goto free_req;
	}

	err = bbdd_jrpc_dissect_request(request_obj, &id, &method, &params,
					&error);
	if (err) {
		bbdd_util_jrpc_respond(&peer,
				       bbdd_jrpc_new_error_inv_request(error));
		free(error);
		goto put_req_obj;
	}

	cb(&peer, method, params, id, data);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
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
