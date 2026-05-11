// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-br.h"

#include <stdio.h>
#include <string.h>

#include "bbdd.h"
#include "bbdd-bfdd.h"
#include "bbdd-mon.h"

static int bbdd_br_do_start(const char *addr,
			    struct bbdd_mon_topics topics)
{
	/* xxx: not yet implemented */
	(void)addr;
	(void)topics;
	fprintf(stderr, "bbdd bfdd bridge start: not yet implemented\n");
	return -1;
}

static void bbdd_br_start_help(void)
{
	fprintf(stderr, "%s",
		"Usage: bbdd bfdd bridge start [TYPE:ADDRESS[:PORT]] [monitor [topics...]]\n"
		"TYPE ::= {ipv4 | ipv6 | unix}\n"
		"Default address is `" BBDD_BFDD_DEFAULT_ADDR "'.\n"
		"\n"
	);
}

int bbdd_br_start(int argc, char **argv)
{
	struct bbdd_mon_topics topics = {};
	const char *addr = BBDD_BFDD_DEFAULT_ADDR;
	int rc;

	if (argc > 0 && strcmp(*argv, "help") == 0) {
		bbdd_br_start_help();
		return 0;
	}

	/* Optional socket address — anything that is not "monitor". */
	if (argc > 0 && strcmp(*argv, "monitor") != 0) {
		addr = *argv;
		NEXT_ARG_FWD();
	}

	if (argc > 0 && strcmp(*argv, "monitor") == 0) {
		NEXT_ARG_FWD();
		rc = bbdd_c_monitor_parse_topics(argc, argv, &topics);
		if (rc != 0)
			return rc;
	} else if (argc > 0) {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		return -1;
	} else {
		topics.enabled[BBDD_MON_TOPIC_error] = true;
	}

	return bbdd_br_do_start(addr, topics);
}
