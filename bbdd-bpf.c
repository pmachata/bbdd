// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <bpf/libbpf.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "bbdd-prog.skel.h"
#pragma GCC diagnostic pop

#include "bbdd.h"

struct bbdd_bpf_attachment {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
};

struct bbdd_bpf {
	struct bbdd_prog *skel;
	struct bbdd_bpf_attachment *rx;
	struct bbdd_bpf_attachment *tx;
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

	bpf->skel = bbdd_prog__open_and_load();
	if (!bpf->skel) {
		if (asprintf(error, "bbdd_prog__open_and_load: %m") < 0)
			*error = NULL;
		goto free_bpf;
	}

	return bpf;

free_bpf:
	free(bpf);
	return NULL;
}

static struct bbdd_bpf_attachment *
bbdd_bpf_attach(struct bpf_program *prog, uint32_t ifindex,
		enum bpf_tc_attach_point attach_point,
		char **error)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = (int)ifindex,
		.attach_point = attach_point,
	};
	struct bbdd_bpf_attachment *attachment;
	struct bpf_tc_opts opts;
	int err;

	attachment = malloc(sizeof(*attachment));
	if (!attachment) {
		if (asprintf(error, "bbdd_bpf_attach: %m") < 0)
			*error = NULL;
		return NULL;
	}

	err = bpf_tc_hook_create(&hook);
	if (err) {
		if (asprintf(error, "bpf_tc_hook_create(ifindex=%u): %s",
			     ifindex, strerror(-err)) < 0)
			*error = NULL;
		goto free;
	}

	opts = (struct bpf_tc_opts) {
		.sz = sizeof(opts),
		.prog_fd = bpf_program__fd(prog),
		.handle = 1,
		.priority = 1,
	};

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		if (asprintf(error, "bpf_tc_attach(ifindex=%u): %s",
			     ifindex, strerror(-err)) < 0)
			*error = NULL;
		goto hook_destroy;
	}

	*attachment = (struct bbdd_bpf_attachment) {
		.hook = hook,
		.opts = opts,
	};
	return attachment;

hook_destroy:
	bpf_tc_hook_destroy(&hook);
free:
	free(attachment);
	return NULL;
}

int bbdd_bpf_attach_veth_rx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error)
{
	bpf->rx = bbdd_bpf_attach(bpf->skel->progs.bbdd_rx, ifindex,
				  BPF_TC_INGRESS, error);
	return bpf->rx != NULL ? 0 : -1;
}

int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error)
{
	bpf->tx = bbdd_bpf_attach(bpf->skel->progs.bbdd_tx, ifindex,
				  BPF_TC_EGRESS, error);
	return bpf->tx != NULL ? 0 : -1;
}

static void bbdd_bpf_detach(struct bbdd_bpf_attachment *attachment)
{
	bpf_tc_detach(&attachment->hook, &attachment->opts);
	free(attachment);
}

void bbdd_bpf_destroy(struct bbdd_bpf *bpf)
{
	if (bpf->rx)
		bbdd_bpf_detach(bpf->rx);
	if (bpf->tx)
		bbdd_bpf_detach(bpf->tx);
	bbdd_prog__destroy(bpf->skel);
	free(bpf);
}
