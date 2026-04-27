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

struct bbdd_mon_cli {
	struct bbdd_mon_cli *prev;
	struct bbdd_mon_cli *next;

	struct bbdd_mon_topics topics;
	struct bbdd_sock sock;
};

struct bbdd_mon {
	struct bbdd_mon_cli *head;	/* DList of clients. */
};

struct bbdd_mon *bbdd_mon_init(void)
{
	struct bbdd_mon *mon;

	mon = malloc(sizeof(*mon));
	if (mon == NULL)
		return NULL;

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

int bbdd_mon_subscribe(struct bbdd_mon *mon, const struct bbdd_sock *sock,
		       struct bbdd_mon_topics topics, char **error)
{
	struct bbdd_mon_cli *cli;

	cli = malloc(sizeof(*cli));
	if (cli == NULL) {
		bbdd_util_fmterr(error, "%m");
		return -1;
	}

	*cli = (struct bbdd_mon_cli) {
		.topics = topics,
		.sock = *sock,
	};

	DL_APPEND(mon->head, cli);
	return 0;
}

int bbdd_mon_send(struct bbdd_mon *mon, struct json_object *msg,
		  enum bbdd_mon_topic topic, char **error)
{
	struct bbdd_mon_cli *cli;
	int ret = 0;

	if (bbdd_env.verbosity > 0) {
		const char *str;

		str = json_object_to_json_string(msg);
		if (str != NULL)
			fprintf(stderr, "%s\n", str);
	}

	DL_FOREACH(mon->head, cli) {
		if (!cli->topics.enabled[topic])
			continue;

		if (bbdd_util_jrpc_send(&cli->sock, msg) != 0) {
			bbdd_util_fmterr(error, "%m");
			ret = -1;
		}
	}

	return ret;
}
