// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <bpf/libbpf.h>

#include "bbdd.h"

struct bbdd_bpf {
};

static int bbdd_bpf_print(enum libbpf_print_level level,
			  const char *fmt, va_list args)
{
	int priority;

	if ((int)level > bbdd_env.verbosity)
		return 0;

	switch (level) {
	case LIBBPF_WARN:
		priority = LOG_WARNING;
		break;
	case LIBBPF_INFO:
		priority = LOG_INFO;
		break;
	case LIBBPF_DEBUG:
	default:
		priority = LOG_DEBUG;
		break;
	}

	vsyslog(priority, fmt, args);
	return 0;
}

struct bbdd_bpf *bbdd_bpf_create(char **error)
{
	struct bbdd_bpf *bpf;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL) {
		if (asprintf(error, "calloc: %m") < 0)
			*error = NULL;
		return NULL;
	}

	libbpf_set_print(bbdd_bpf_print);

	return bpf;
}

void bbdd_bpf_destroy(struct bbdd_bpf *bpf)
{
	free(bpf);
}
