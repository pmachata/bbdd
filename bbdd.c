// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd.h"

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

struct bbdd_env bbdd_env = {
	.verbosity = 0,
};
const char *program_version = "bbdd 0.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

static int bbdd_help(void)
{
	puts("bbdd, the BPF-based BFD dataplane daemon.\n"
	     "\n"
	     "Usage: bbdd [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
	     "                    -V | --version | --sockdir <DIR> | --json |\n"
	     "                    -N | -t | --timestamp ]\n"
	     "	     COMMAND := { start | stop | ping | session | global | bfdd | monitor }\n"
	     "\n"
	     "  -N             suppress human-readable unit conversion (show raw microseconds)\n"
	     "  -t/--timestamp prefix monitor notifications with a timestamp\n"
	     );
	return 0;
}

static int bbdd_cmd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		return bbdd_help();
	} else if (strcmp(*argv, "start") == 0) {
		NEXT_ARG_FWD();
		return bbdd_d_start(argc, argv);
	} else if (strcmp(*argv, "stop") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_stop(argc, argv);
	} else if (strcmp(*argv, "ping") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_ping(argc, argv);
	} else if (strcmp(*argv, "session") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_session(argc, argv);
	} else if (strcmp(*argv, "global") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_global(argc, argv);
	} else if (strcmp(*argv, "bfdd") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_bfdd(argc, argv);
	} else if (strcmp(*argv, "monitor") == 0) {
		NEXT_ARG_FWD();
		return bbdd_c_monitor(argc, argv);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return -EINVAL;
}

int main(int argc, char **argv)
{
	enum {
		opt_sockaddr = 257,
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
		{ "sockdir",	required_argument, NULL, opt_sockaddr },
		{ "debug",	required_argument, NULL, opt_debug },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int rc;

	bbdd_env.sockdir = BBDD_DEFAULT_SOCKDIR;
	while ((opt = getopt_long(argc, argv, "hqtvVN",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("%s\n", program_version);
			return EXIT_SUCCESS;
		case 'h':
			bbdd_help();
			return EXIT_SUCCESS;
		case 'v':
			bbdd_env.verbosity++;
			break;
		case 'q':
			bbdd_env.verbosity--;
			break;
		case opt_sockaddr:
			bbdd_env.sockdir = optarg;
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
			if (strcmp(optarg, "mon-eager") == 0) {
				bbdd_env.mon_eager = true;
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

	rc = bbdd_cmd(argc, argv);
	if (rc != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
