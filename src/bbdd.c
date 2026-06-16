// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include "bbdd.h"

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bbdd-c.h"
#include "bbdd-d.h"
#include "bbdd-err.h"
#include "bbdd-mon.h"
#include "bbdd-util.h"
#include "config.h"

struct bbdd_env bbdd_env = {
	.verbosity = 0,
};
const char *program_version = "bbdd 0.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

const struct bbdd_ec bbdd_ec_success = {
	.__ec = EXIT_SUCCESS,
};
const struct bbdd_ec bbdd_ec_failure = {
	.__ec = EXIT_FAILURE,
};

bool bbdd_ec_is_success(struct bbdd_ec ec)
{
	return ec.__ec == bbdd_ec_success.__ec;
}

static struct bbdd_ec bbdd_help(void)
{
	puts("bbdd, the BPF-based BFD dataplane daemon.\n"
	     "\n"
	     "Usage: bbdd [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
	     "                    -V | --version | --socket <PATH> | --json |\n"
	     "                    -N | -t | --timestamp ]\n"
	     "	     COMMAND := { start | stop | echo | session | global | bfdd | monitor }\n"
	     "\n"
	     "  --json         show JSON result object instead of formatting it\n"
	     "  -N             suppress human-readable unit conversion (show raw microseconds)\n"
	     "  --socket       path to the UNIX socket used to talk to the daemon\n"
	     "                 defaults to " BBDD_DEFAULT_SOCKET "\n"
	     "  -t/--timestamp prefix monitor notifications with a timestamp\n"
	     );
	return bbdd_ec_success;
}

static struct bbdd_ec
bbdd_cmd(int argc, char **argv, const struct bbdd_mon_topics *topics)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		return bbdd_help();
	} else if (strcmp(*argv, "start") == 0) {
		NEXT_ARG_FWD();
		return bbdd_d_start(argc, argv, topics);
	} else if (strcmp(*argv, "stop") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_stop(argc, argv, topics);
	} else if (strcmp(*argv, "echo") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_echo(argc, argv, topics);
	} else if (strcmp(*argv, "session") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_session(argc, argv, topics);
	} else if (strcmp(*argv, "global") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_global(argc, argv, topics);
	} else if (strcmp(*argv, "bfdd") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd(argc, argv, topics);
	} else if (strcmp(*argv, "monitor") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_monitor(argc, argv, topics);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return bbdd_ec_failure;
}

int main(int argc, char **argv)
{
	enum {
		opt_socket = 257,
		opt_json,
		opt_debug,
	};
	static const struct option long_options[] = {
		{ "help",	no_argument,	   NULL, 'h' },
		{ "json",	no_argument,	   NULL, opt_json },
		{ "quiet",	no_argument,	   NULL, 'q' },
		{ "timestamp",	no_argument,	   NULL, 't' },
		{ "verbose",	no_argument,	   NULL, 'v' },
		{ "version",	no_argument,	   NULL, 'V' },
		{ "socket",	required_argument, NULL, opt_socket },
		{ "debug",	required_argument, NULL, opt_debug },
		{ NULL, 0, NULL, 0 }
	};
	struct bbdd_mon_topics topics = {};
	struct bbdd_ec ec;
	int verbosity = 0;
	char *error;
	int opt;
	int rc;

	bbdd_env.socket = BBDD_DEFAULT_SOCKET;
	while ((opt = getopt_long(argc, argv, "hqtvVN",
				  long_options, NULL)) >= 0) {
		switch (opt) {
			const char *dbg_arg;
			uint32_t us;

		case 'V':
			printf("%s\n", program_version);
			return EXIT_SUCCESS;
		case 'h':
			bbdd_help();
			return EXIT_SUCCESS;
		case 'v':
			verbosity++;
			break;
		case 'q':
			verbosity--;
			break;
		case opt_socket:
			bbdd_env.socket = optarg;
			break;
		case opt_json:
			bbdd_env.show_json = true;
			break;
		case 'N':
			bbdd_env.numeric = true;
			break;
		case 't':
			bbdd_env.timestamp = true;
			break;
		case opt_debug:
			if (bbdd_util_startswith(optarg, "bfdd-delay=",
						 &dbg_arg)) {
				rc = bbdd_util_parse_time_us(dbg_arg, &us,
							     &error);
				if (rc != 0) {
					bbdd_err_print(&error, "bfdd-delay `%s'",
						       dbg_arg);
					return EXIT_FAILURE;
				}
				bbdd_env.bfdd_delay_ms = us;
			} else if (strcmp(optarg, "cli-imm-done") == 0) {
				bbdd_env.cli_imm_done = true;
			} else if (strcmp(optarg, "mon-eager") == 0) {
				bbdd_env.mon_eager = true;
			} else if (strcmp(optarg, "no-poll-reply") == 0) {
				bbdd_env.no_poll_reply = true;
			} else {
				fprintf(stderr, "Unknown --debug value: %s\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			bbdd_help();
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	if (verbosity >= 0)
		topics.enabled[BBDD_MON_TOPIC_error] = true;
	if (verbosity >= 1)
		topics.enabled[BBDD_MON_TOPIC_debug] = true;
	bbdd_env.verbosity = verbosity;
	bbdd_err_verbosity = verbosity;

	ec = bbdd_cmd(argc, argv, &topics);
	return ec.__ec;
}
