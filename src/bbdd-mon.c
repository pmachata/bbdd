// SPDX-License-Identifier: GPL-2.0
#include "bbdd-mon.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <utlist.h>

#include "bbdd-err.h"
#include "bbdd-jrpc.h"
#include "bbdd-sock.h"
#include "bbdd-util.h"

enum bbdd_mon_cli_kind {
	BBDD_MON_CLI_KIND_SOCK,
	BBDD_MON_CLI_KIND_CB,
};

struct bbdd_mon_cli {
	struct bbdd_mon_cli *prev;
	struct bbdd_mon_cli *next;

	struct bbdd_mon_topics topics;

	enum bbdd_mon_cli_kind kind;
	union {
		struct bbdd_sock sock;
		struct {
			void (*cb)(struct json_object *, void *);
			void *data;
		};
	};
};

struct bbdd_mon {
	struct bbdd_mon_cli *head;	/* DList of clients. */
	unsigned int active[bbdd_mon_ntopics];
	bool eager;
};

struct bbdd_mon *bbdd_mon_init(bool eager, char **error)
{
	struct bbdd_mon *mon;

	mon = malloc(sizeof(*mon));
	if (mon == NULL) {
		bbdd_err_fmt(error, "Failed to create monitor server: %m");
		return NULL;
	}

	*mon = (struct bbdd_mon) {
		.eager = eager,
	};
	return mon;
}

void bbdd_mon_fini(struct bbdd_mon *mon)
{
	struct bbdd_mon_cli *cli, *tmp;

	DL_FOREACH_SAFE(mon->head, cli, tmp) {
		DL_DELETE(mon->head, cli);
		free(cli);
	}

	free(mon);
}

static struct bbdd_mon_cli *
bbdd_mon_alloc_client(struct bbdd_mon *mon, struct bbdd_mon_topics topics,
		      char **error)
{
	struct bbdd_mon_cli *cli;

	cli = malloc(sizeof(*cli));
	if (cli == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	*cli = (struct bbdd_mon_cli) {
		.topics = topics,
	};

	DL_APPEND(mon->head, cli);

	for (int i = 0; i < bbdd_mon_ntopics; i++)
		if (topics.enabled[i])
			mon->active[i]++;

	return cli;
}

int bbdd_mon_subscribe(struct bbdd_mon *mon, const struct bbdd_sock *sock,
		       struct bbdd_mon_topics topics, char **error)
{
	struct bbdd_mon_cli *cli;

	topics.enabled[BBDD_MON_TOPIC_monitor] = true;
	cli = bbdd_mon_alloc_client(mon, topics, error);
	if (cli == NULL) {
		bbdd_err_app(error, "Failed to subscribe to monitor");
		return -1;
	}

	cli->kind = BBDD_MON_CLI_KIND_SOCK;
	cli->sock = *sock;
	return 0;
}

int bbdd_mon_subscribe_cb(struct bbdd_mon *mon,
			  void (*cb)(struct json_object *, void *), void *data,
			  struct bbdd_mon_topics topics, char **error)
{
	struct bbdd_mon_cli *cli;

	topics.enabled[BBDD_MON_TOPIC_monitor] = false;
	cli = bbdd_mon_alloc_client(mon, topics, error);
	if (cli == NULL) {
		bbdd_err_app(error, "Failed to subscribe to monitor");
		return -1;
	}

	cli->kind = BBDD_MON_CLI_KIND_CB;
	cli->cb = cb;
	cli->data = data;
	return 0;
}

static void bbdd_mon_unsubscribe(struct bbdd_mon *mon, struct bbdd_mon_cli *cli)
{
	for (int i = 0; i < bbdd_mon_ntopics; i++)
		if (cli->topics.enabled[i])
			mon->active[i]--;

	DL_DELETE(mon->head, cli);
	free(cli);
}

bool bbdd_mon_topic_active(struct bbdd_mon *mon, enum bbdd_mon_topic topic)
{
	return mon->eager || mon->active[topic] > 0;
}

static void __bbdd_mon_send(struct bbdd_mon *mon, struct json_object *msg,
			    enum bbdd_mon_topic topic)
{
	struct bbdd_mon_cli *cli;
	struct bbdd_mon_cli *tmp;

	DL_FOREACH_SAFE(mon->head, cli, tmp) {
		if (!cli->topics.enabled[topic])
			continue;

		switch (cli->kind) {
		case BBDD_MON_CLI_KIND_SOCK:
			if (bbdd_util_jrpc_send(&cli->sock, msg, NULL) != 0)
				bbdd_mon_unsubscribe(mon, cli);
			break;

		case BBDD_MON_CLI_KIND_CB:
			cli->cb(msg, cli->data);
			break;
		}
	}
}

void bbdd_mon_send(struct bbdd_mon *mon, struct bbdd_mon_message *mon_msg,
		   enum bbdd_mon_topic topic)
{
	struct json_object *outer_params;
	struct json_object *notif;
	struct timespec ts;
	uint64_t ts_ms;

	assert(mon_msg->method != NULL);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

	outer_params = json_object_new_object();
	if (outer_params == NULL)
		goto put_params;

	bbdd_jrpc_append_uint64(outer_params, "ts", ts_ms); /* ignore failure */

	if (bbdd_jrpc_append_obj(outer_params, "params", &mon_msg->params) != 0)
		goto put_outer;

	notif = bbdd_jrpc_new_notif(mon_msg->method);
	if (notif == NULL)
		goto put_outer;

	if (bbdd_jrpc_append_obj(notif, "params", &outer_params) != 0)
		goto put_notif;

	__bbdd_mon_send(mon, notif, topic);

put_notif:
	json_object_put(notif);
put_outer:
	json_object_put(outer_params);
put_params:
	json_object_put(mon_msg->params); /* NULL-safe after successful append_obj */

	mon_msg->params = bbdd_poison;
}

static void bbdd_mon_send_str(struct bbdd_mon *mon, enum bbdd_mon_topic topic,
			      const char *method, const char *str)
{
	struct json_object *params = NULL;
	struct bbdd_mon_message mon_msg;
	int rc;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	if (str != NULL) {
		params = json_object_new_object();
		if (params == NULL)
			return;

		rc = bbdd_jrpc_append_str(params, "msg", str);
		if (rc != 0)
			goto put_params;
	}

	mon_msg = (struct bbdd_mon_message) {
		.method = method,
		.params = params,
	};
	return bbdd_mon_send(mon, &mon_msg, topic);

put_params:
	json_object_put(params);
}

static void bbdd_mon_send_vfmt(struct bbdd_mon *mon, enum bbdd_mon_topic topic,
			       const char *method, const char *fmt, va_list ap)
{
	char *msg;
	int rc;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	rc = bbdd_err_vfmt(&msg, fmt, ap);
	if (rc < 0)
		return;

	bbdd_mon_send_str(mon, topic, method, msg);
	free(msg);
}

__attribute__((format(printf, 2, 3)))
void bbdd_mon_send_debug(struct bbdd_mon *mon, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bbdd_mon_send_vfmt(mon, BBDD_MON_TOPIC_debug, "debug", fmt, ap);
	va_end(ap);
}

__attribute__((format(printf, 3, 4)))
void bbdd_mon_senderr(struct bbdd_mon *mon, char **error, const char *fmt, ...)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_error;
	const char *method = "error";
	const char *errmsg;
	char *str = NULL;
	va_list ap;
	int rc;

	errmsg = *error ?: "(unknown error)";

	va_start(ap, fmt);
	rc = bbdd_err_vfmt(&str, fmt, ap);
	va_end(ap);

	if (rc < 0) {
		bbdd_mon_send_str(mon, topic, method, errmsg);
		goto out;
	}

	if (*error != NULL)
		/* str is unchanged if the formatting fails. */
		bbdd_err_wrap(&str, "%s: %s", str, *error);

	bbdd_mon_send_str(mon, topic, method, str);

out:
	free(str);
	free(*error);
	*error = NULL;
}

void bbdd_mon_send_monitor_end(struct bbdd_mon *mon)
{
	bbdd_mon_send_str(mon, BBDD_MON_TOPIC_monitor, "monitor-end", NULL);
}
