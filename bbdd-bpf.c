// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <bpf/libbpf.h>
#include <json-c/json_object.h>

#include "bbdd.h"
#include "bbdd-jrpc.h"
#include "bbdd-prog.h"

#define FIELD(NAME) uint64_t NAME;
struct bbdd_prog_stats {
	BBDD_GLOBAL_STATS(FIELD)
};
#undef FIELD

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "bbdd-prog.skel.h"
#pragma GCC diagnostic pop

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
	bpf->skel->bss->bbdd_veth_tx_ifindex = (int)ifindex;
	bpf->tx = bbdd_bpf_attach(bpf->skel->progs.bbdd_tx, ifindex,
				  BPF_TC_EGRESS, error);
	return bpf->tx != NULL ? 0 : -1;
}

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    uint32_t lid,
			    uint32_t ifindex,
			    const struct bbdd_sockaddr *src,
			    const struct bbdd_sockaddr *dst,
			    uint32_t tbid,
			    uint32_t flags,
			    uint64_t min_interval,
			    uint64_t max_interval,
			    char **error)
{
	int af = src->sa.sa_family;
	struct bbdd_bfd_session_config config = {
		.fib_lookup = {
			.family  = (uint8_t) af,
			.ifindex = ifindex,
			.tbid    = tbid,
		},
		.bpf_fib_lookup_flags = flags,
		.min_interval         = min_interval,
		.max_interval         = max_interval,
	};
	int err;

	if (af != dst->sa.sa_family) {
		bbdd_jrpc_fmterr(error, "Mismatch in families of source and destination addresses");
		return -1;
	}

	switch (af) {
	case AF_INET:
		config.fib_lookup.ipv4_src = src->sin.sin_addr.s_addr;
		config.fib_lookup.ipv4_dst = dst->sin.sin_addr.s_addr;
		config.fib_lookup.sport = src->sin.sin_port;
		config.fib_lookup.dport = dst->sin.sin_port;
		break;
	case AF_INET6:
		memcpy(config.fib_lookup.ipv6_src, &src->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_src));
		memcpy(config.fib_lookup.ipv6_dst, &dst->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_dst));
		config.fib_lookup.sport = src->sin6.sin6_port;
		config.fib_lookup.dport = dst->sin6.sin6_port;
		break;
	default:
		bbdd_jrpc_fmterr(error, "Unsupported session address family %d",
				 af);
		return -1;
	}

	{
		struct bbdd_bfd_session_config old;

		err = bpf_map__lookup_elem(
			bpf->skel->maps.bbdd_bpf_session_config_hash,
			&lid, sizeof(lid),
			&old, sizeof(old), 0);

		if (err)
			config.gen_id = 1;
		else
			config.gen_id = old.gen_id + 1;
	}

	err = bpf_map__update_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
				   &lid, sizeof(lid),
				   &config, sizeof(config),
				   BPF_ANY);
	if (err) {
		bbdd_jrpc_fmterr(error, "bpf_map__update_elem: %s",
				 strerror(-err));
		return -1;
	}

	return 0;
}

int bbdd_bpf_session_delete(struct bbdd_bpf *bpf, uint32_t lid,
			    char **error)
{
	int err;

	err = bpf_map__delete_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
				   &lid, sizeof(lid), 0);
	if (err)
		bbdd_jrpc_fmterr(error, "session %u: bpf_map__delete_elem: %s",
				 lid, strerror(-err));
	return err;
}

static void bbdd_bpf_detach(struct bbdd_bpf_attachment *attachment)
{
	bpf_tc_detach(&attachment->hook, &attachment->opts);
	free(attachment);
}

struct json_object *bbdd_bpf_global_stats_json(struct bbdd_bpf *bpf,
					       char **error)
{
	struct bbdd_prog_stats *stats = &bpf->skel->bss->bbdd_stats;
	struct json_object *obj;

	obj = json_object_new_object();
	if (!obj) {
		if (asprintf(error, "Failed to format global stats to JSON: %m") < 0)
			*error = NULL;
		return NULL;
	}

#define FIELD(NAME)							\
	if (json_object_object_add(obj, #NAME,				\
				   json_object_new_uint64(stats->NAME))) { \
		if (asprintf(error,					\
			     "Failed to format global stats to JSON: %m") < 0) \
			*error = NULL;					\
		goto err;						\
	}
	BBDD_GLOBAL_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
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
