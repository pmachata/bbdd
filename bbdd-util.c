// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json_tokener.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-mon.h"
#include "bbdd-sock.h"

int bbdd_util_vfmterr(char **strp, const char *fmt, va_list ap)
{
	int rc;

	if (!strp)
		return 0;

	rc = vasprintf(strp, fmt, ap);
	if (rc < 0)
		*strp = NULL;
	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vfmterr(strp, fmt, ap);
	va_end(ap);

	return rc;
}

static int bbdd_util_vwraperr(char **strp, const char *fmt, va_list ap)
{
	char *new_strp = NULL;
	int rc;

	rc = bbdd_util_vfmterr(&new_strp, fmt, ap);
	if (rc >= 0) {
		free(*strp);
		*strp = new_strp;
	}

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_wraperr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vwraperr(strp, fmt, ap);
	va_end(ap);

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_appenderr(char **error, const char *fmt, ...)
{
	char *msg;
	va_list ap;
	int rc;

	if (error == NULL)
		return 0;

	va_start(ap, fmt);
	rc = bbdd_util_vfmterr(&msg, fmt, ap);
	va_end(ap);

	if (rc < 0)
		return rc;

	if (*error != NULL)
		rc = bbdd_util_wraperr(&msg, "%s: %s", msg, *error);

	/* When the wraperr call fails, we are left with just the fmt message.
	 * But that seems like the more important message to have. A low-level
	 * error is arguably worth less than where the error happened. */
	free(*error);
	*error = msg;
	return rc;
}

static void bbdd_util_vprinterr(char **error, const char *fmt, va_list ap)
{
	if (bbdd_env.verbosity < 0)
		return;

	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);

	if (*error) {
		fprintf(stderr, "%s%s\n",
			fmt != NULL ? ": " : "", *error);
		free(*error);
	}
}

__attribute__((format(printf, 2, 3)))
void bbdd_util_printerr(char **error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bbdd_util_vprinterr(error, fmt, ap);
	va_end(ap);
}

int bbdd_util_pickerr(int rc1, char **error1, int rc2, char **error2)
{
	if (rc1 == 0 && rc2 == 0)
		return 0;

	if (rc1 != 0 && rc2 != 0) {
		free(*error2);
		*error2 = NULL;
		return rc1;
	}

	if (rc2 != 0) {
		*error1 = *error2;
		*error2 = NULL;
		return rc2;
	}

	return rc1;
}

void bbdd_util_xferr(char **error, char **src)
{
	if (error == NULL)
		return;
	*error = *src;
	*src = NULL;
}

int bbdd_util_jrpc_send(struct bbdd_sock *sock, struct json_object *obj)
{
	const char *str;
	size_t len;
	ssize_t rc;

	str = json_object_to_json_string(obj);
	if (str == NULL)
		return -1;

	len = strlen(str);
	rc = sendto(sock->fd, str, len, 0,
		    (struct sockaddr *) &sock->sa, sock->sa.len);
	if (rc < 0)
		return -1;
	return (size_t)rc == len ? 0 : -1;
}

void bbdd_util_jrpc_respond(struct bbdd_sock *ctl, struct json_object *obj)
{
	if (obj != NULL) {
		bbdd_util_jrpc_send(ctl, obj);
		json_object_put(obj);
	}
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

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (json_object_object_add(obj, "result", NULL))
		goto put_obj;

	bbdd_util_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
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

	err = bbdd_sock_recv(ctl, &peer, &request);
	if (err < 0)
		return;

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
