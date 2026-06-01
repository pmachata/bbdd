/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <json-c/json_object.h>

#include "bbdd-mon.i"
#include "bbdd-sock.i"

/* The elements are (name, monitor-default), where the latter indicates whether
 * it makes for 'bbdd monitor' to monitor the topic by default. */
#define BBDD_MON_TOPICS(X)	\
	X(ringbuf, true)	\
	X(bfddi,   true)	\
	X(bfddo,   true)	\
	X(jrpc,    false)	\
	X(session, true)	\
	X(error,   true)	\
	X(debug,   false)	\
	/**/

#define BBDD_MON_ENUM(NAME, ALL) BBDD_MON_TOPIC_ ## NAME,
enum bbdd_mon_topic {
	BBDD_MON_TOPIC_monitor,
	BBDD_MON_TOPICS(BBDD_MON_ENUM)
	bbdd_mon_ntopics
};
#undef BBDD_MON_ENUM

struct bbdd_mon_topics {
	bool enabled[bbdd_mon_ntopics];
};

struct bbdd_mon *bbdd_mon_init(char **error);
void bbdd_mon_fini(struct bbdd_mon *mon);

int bbdd_mon_subscribe(struct bbdd_mon *mon, const struct bbdd_sock *sock,
		       struct bbdd_mon_topics topics, char **error);

int bbdd_mon_subscribe_cb(struct bbdd_mon *mon,
			  void (*cb)(struct json_object *, void *),
			  void *data, struct bbdd_mon_topics topics,
			  char **error);

bool bbdd_mon_topic_active(struct bbdd_mon *mon, enum bbdd_mon_topic topic);

struct bbdd_mon_message {
	const char *method;
	struct json_object *params;
};
void bbdd_mon_send(struct bbdd_mon *mon, struct bbdd_mon_message *mon_msg,
		   enum bbdd_mon_topic topic);

__attribute__((format(printf, 2, 3)))
void bbdd_mon_send_debug(struct bbdd_mon *mon, const char *fmt, ...);

__attribute__((format(printf, 3, 4)))
void bbdd_mon_senderr(struct bbdd_mon *mon, char **error, const char *fmt, ...);

void bbdd_mon_send_monitor_end(struct bbdd_mon *mon);
