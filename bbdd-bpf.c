// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <bpf/libbpf.h>

#include "bbdd.h"

struct bbdd_bpf {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_tc_hook tx_hook;
	struct bpf_tc_opts tx_opts;
	bool tx_attached;
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
	int err;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL) {
		if (asprintf(error, "calloc: %m") < 0)
			*error = NULL;
		return NULL;
	}

	libbpf_set_print(bbdd_bpf_print);

	bpf->obj = bpf_object__open(BBDD_BPF_PROG_PATH);
	if (!bpf->obj) {
		if (asprintf(error, "bpf_object__open(%s): %m",
			     BBDD_BPF_PROG_PATH) < 0)
			*error = NULL;
		goto free_bpf;
	}

	err = bpf_object__load(bpf->obj);
	if (err) {
		if (asprintf(error, "bpf_object__load: %s", strerror(-err)) < 0)
			*error = NULL;
		goto close_obj;
	}

	bpf->prog = bpf_object__find_program_by_name(bpf->obj, "bbdd_tx");
	if (!bpf->prog) {
		if (asprintf(error, "program `bbdd_tx' not found in `%s'",
			     BBDD_BPF_PROG_PATH) < 0)
			*error = NULL;
		goto close_obj;
	}

	return bpf;

close_obj:
	bpf_object__close(bpf->obj);
free_bpf:
	free(bpf);
	return NULL;
}

int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = (int)ifindex,
		.attach_point = BPF_TC_EGRESS,
	};
	struct bpf_tc_opts opts = {
		.sz = sizeof(opts),
		.prog_fd = bpf_program__fd(bpf->prog),
		.handle = 1,
		.priority = 1,
	};
	int err;

	err = bpf_tc_hook_create(&hook);
	if (err) {
		if (asprintf(error, "bpf_tc_hook_create(ifindex=%u): %s",
			     ifindex, strerror(-err)) < 0)
			*error = NULL;
		return -1;
	}

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		if (asprintf(error, "bpf_tc_attach(ifindex=%u): %s",
			     ifindex, strerror(-err)) < 0)
			*error = NULL;
		return -1;
	}

	bpf->tx_hook = hook;
	bpf->tx_opts = opts;
	bpf->tx_attached = true;
	return 0;
}

void bbdd_bpf_destroy(struct bbdd_bpf *bpf)
{
	if (bpf->tx_attached)
		bpf_tc_detach(&bpf->tx_hook, &bpf->tx_opts);
	bpf_object__close(bpf->obj);
	free(bpf);
}
