// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-mon.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <utlist.h>

#include "bbdd.h"
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
};

struct bbdd_mon *bbdd_mon_init(char **error)
{
	struct bbdd_mon *mon;

	mon = malloc(sizeof(*mon));
	if (mon == NULL) {
		bbdd_util_fmterr(error, "Failed to create monitor server: %m");
		return NULL;
	}

	*mon = (struct bbdd_mon) {};
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
		bbdd_util_fmterr(error, "%m");
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
		bbdd_util_appenderr(error, "Failed to subscribe to monitor");
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
		bbdd_util_appenderr(error, "Failed to subscribe to monitor");
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
	return bbdd_env.mon_eager || mon->active[topic] > 0;
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
			if (bbdd_util_jrpc_send(&cli->sock, msg) != 0)
				bbdd_mon_unsubscribe(mon, cli);
			break;

		case BBDD_MON_CLI_KIND_CB:
			cli->cb(msg, cli->data);
			break;
		}
	}
}

void bbdd_mon_send(struct bbdd_mon *mon, struct json_object *msg,
		   enum bbdd_mon_topic topic)
{
	__bbdd_mon_send(mon, msg, topic);
}

static void bbdd_mon_send_msg(struct bbdd_mon *mon, enum bbdd_mon_topic topic,
			      const char *method, const char *msg)
{
	struct json_object *params;
	struct json_object *obj;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	obj = bbdd_jrpc_new_notif(method);
	if (obj == NULL)
		return;

	params = json_object_new_object();
	if (params == NULL)
		goto put_obj;

	if (bbdd_jrpc_append_str(params, "msg", msg) ||
	    bbdd_jrpc_append_obj(obj, "params", &params))
		goto put_params;

	__bbdd_mon_send(mon, obj, topic);

put_params:
	json_object_put(params);
put_obj:
	json_object_put(obj);
}

static void bbdd_mon_send_vfmt(struct bbdd_mon *mon, enum bbdd_mon_topic topic,
			       const char *method, const char *fmt, va_list ap)
{
	char *msg;
	int rc;

	if (!bbdd_mon_topic_active(mon, topic))
		return;

	rc = bbdd_util_vfmterr(&msg, fmt, ap);
	if (rc < 0)
		return;

	bbdd_mon_send_msg(mon, topic, method, msg);
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
	rc = bbdd_util_vfmterr(&str, fmt, ap);
	va_end(ap);

	if (rc < 0) {
		bbdd_mon_send_msg(mon, topic, method, errmsg);
		goto out;
	}

	if (*error != NULL)
		/* str is unchanged if the formatting fails. */
		bbdd_util_wraperr(&str, "%s: %s", str, *error);

	bbdd_mon_send_msg(mon, topic, method, str);

out:
	free(str);
	free(*error);
	*error = NULL;
}

void bbdd_mon_send_monitor_end(struct bbdd_mon *mon)
{
	enum bbdd_mon_topic topic = BBDD_MON_TOPIC_monitor;
	struct json_object *notif;

	notif = bbdd_jrpc_new_notif("monitor-end");
	if (notif == NULL)
		return;

	__bbdd_mon_send(mon, notif, topic);
	json_object_put(notif);
}
