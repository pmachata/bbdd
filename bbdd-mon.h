/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once
#include <json-c/json_object.h>

/* bbdd-sock.c */

struct bbdd_sock;

/* bbdd-mon.c */

struct bbdd_mon;

#define BBDD_MON_TOPICS(X)	\
	X(ringbuf)		\
	X(session)		\
	/**/

#define ENUM(NAME) BBDD_MON_TOPIC_ ## NAME,
enum bbdd_mon_topic {
	BBDD_MON_TOPICS(ENUM)
};
#undef ENUM

#define PLUS1(NAME) +1
enum {
	bbdd_mon_ntopics = BBDD_MON_TOPICS(PLUS1)
};
#undef PLUS1

struct bbdd_mon_topics {
	bool enabled[bbdd_mon_ntopics];
};

struct bbdd_mon *bbdd_mon_init(void);
void bbdd_mon_fini(struct bbdd_mon *mon);

int bbdd_mon_subscribe(struct bbdd_mon *mon, const struct bbdd_sock *sock,
		       struct bbdd_mon_topics topics, char **error);

void bbdd_mon_broadcast(struct bbdd_mon *mon, struct json_object *msg);
void bbdd_mon_send(struct bbdd_mon *mon, struct json_object *msg,
		   enum bbdd_mon_topic topic);
