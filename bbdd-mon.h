/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once
#include <json-c/json_object.h>

/* bbdd-sock.c */

struct bbdd_sock;

/* bbdd-mon.c */

struct bbdd_mon;

#define BBDD_MON_TOPICS(X)	\
	X(ringbuf, true)	\
	X(bfdd,    true)	\
	X(session, true)	\
	X(error,   true)	\
	X(debug,   false)	\
	/**/

#define BBDD_MON_ENUM(NAME, ALL) BBDD_MON_TOPIC_ ## NAME,
enum bbdd_mon_topic {
	BBDD_MON_TOPICS(BBDD_MON_ENUM)
};
#undef BBDD_MON_ENUM

#define BBDD_MON_PLUS1(NAME, ALL) +1
enum {
	bbdd_mon_ntopics = BBDD_MON_TOPICS(BBDD_MON_PLUS1)
};
#undef BBDD_MON_PLUS1

struct bbdd_mon_topics {
	bool enabled[bbdd_mon_ntopics];
};

struct bbdd_mon *bbdd_mon_init(void);
void bbdd_mon_fini(struct bbdd_mon *mon);

int bbdd_mon_subscribe(struct bbdd_mon *mon, const struct bbdd_sock *sock,
		       struct bbdd_mon_topics topics, char **error);

int bbdd_mon_subscribe_cb(struct bbdd_mon *mon,
			  void (*cb)(struct json_object *, void *), void *data,
			  struct bbdd_mon_topics topics, char **error);

bool bbdd_mon_topic_active(struct bbdd_mon *mon, enum bbdd_mon_topic topic);
void bbdd_mon_send(struct bbdd_mon *mon, struct json_object *msg,
		   enum bbdd_mon_topic topic);

__attribute__((format(printf, 2, 3)))
void bbdd_mon_send_debug(struct bbdd_mon *mon, const char *fmt, ...);

__attribute__((format(printf, 3, 4)))
void bbdd_mon_senderr(struct bbdd_mon *mon, char **error, const char *fmt, ...);

void bbdd_mon_send_monitor_end(struct bbdd_mon *mon);
