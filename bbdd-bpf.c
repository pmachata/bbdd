// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE

#include "bbdd-bpf.h"

#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include <bpf/libbpf.h>
#include <json-c/json_object.h>

#include "bbdd.h"
#include "bbdd-nl.h"
#include "bbdd-prog.h"
#include "bbdd-util.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "bbdd-prog.skel.h"
#pragma GCC diagnostic pop

struct bbdd_bpf_attachment {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
};

/* Interface between bbdd_bpf_rb_recv() and bbdd_bpf_rb_handle(). */
struct bbdd_bpf_rb_context {
	struct bbdd_bpf *bpf;
	struct ring_buffer *rb;
	struct bbdd_nl *nl;
	struct bbdd_sess_dir *sdir;
	char **error;
};

struct bbdd_bpf {
	struct bbdd_prog *skel;
	struct bbdd_bpf_attachment *rx;
	struct bbdd_bpf_attachment *tx;
	struct bbdd_bpf_rb_context *rb_ctx;
};

static int bbdd_bpf_print(enum libbpf_print_level level,
			  const char *fmt, va_list args)
{
	if ((int)level <= bbdd_env.verbosity)
		vfprintf(stderr, fmt, args);
	return 0;
}

static int
bbdd_bpf_addr_to_sockaddr(uint16_t ethtype,
			  const struct bbdd_bpf_addr *bfd_addr,
			  struct bbdd_sockaddr *addr,
			  const char *context,
			  char **error)
{
	switch (ethtype) {
	case ETH_P_IP:
		addr->sa.sa_family = AF_INET;
		memcpy(&addr->sin.sin_addr, bfd_addr->addr,
		       sizeof(addr->sin.sin_addr));
		addr->len = sizeof(addr->sin);
		return 0;
	case ETH_P_IPV6:
		addr->sa.sa_family = AF_INET6;
		memcpy(&addr->sin6.sin6_addr, bfd_addr->addr,
		       sizeof(addr->sin6.sin6_addr));
		addr->len = sizeof(addr->sin6);
		return 0;
	}

	bbdd_util_fmterr(error, "%s: invalid ethtype %#x", context, ethtype);
	return -EPROTO;
}

static int
bbdd_bpf_rb_handle_no_neighbor(const struct bbdd_bpf_rb_elem_tx_no_neighbor *elem,
			       struct bbdd_nl *nl, char **error)
{
	struct bbdd_sockaddr addr = {};
	int err;

	err = bbdd_bpf_addr_to_sockaddr(elem->ethtype, &elem->addr, &addr,
					"BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR",
					error);
	if (err)
		return err;

	return bbdd_nl_refresh_neigh(nl, (uint32_t)elem->ifindex, &addr, error);
}

static int
bbdd_bpf_rb_handle_discr_0(const struct bbdd_bpf_rb_elem_rx_discr_0 *elem)
{
	fprintf(stderr, "RX: discrimininator 0 iif %d ethtype %d ttl %d multihop %d\n",
		elem->ifindex, elem->ethtype, elem->ttl, elem->multihop);
	return 0;
}

static int bbdd_bpf_rb_handle(void *ctx, void *data, size_t)
{
	struct bbdd_bpf_rb_context *rb_ctx = ctx;
	const struct bbdd_bpf_rb_elem_head *head = data;

	switch (head->type) {
	case BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR:
		return bbdd_bpf_rb_handle_no_neighbor(data, rb_ctx->nl,
						      rb_ctx->error);
	case BBDD_BPF_RB_ELEM_RX_DISCR_0:
		return bbdd_bpf_rb_handle_discr_0(data, rb_ctx->sdir,
						  rb_ctx->error);
	case BBDD_BPF_RB_ELEM_RX_UNX_PACKET:
	case BBDD_BPF_RB_ELEM_RX_TIMEOUT:
		fprintf(stderr, "unhandled RB event type %d\n", head->type);
		break;
	}
	return 0;
}

static int bbdd_bpf_rb_recv(struct bbdd_poll_ctx *, void *data, char **error)
{
	struct bbdd_bpf_rb_context *rb_ctx = data;
	int ret;

	rb_ctx->error = error;
	ret = ring_buffer__consume(rb_ctx->rb);
	if (ret < 0) {
		bbdd_util_fmterr(error, "ring_buffer__consume: %s",
				 strerror(-ret));
		return -1;
	}
	rb_ctx->error = NULL;

	return 0;
}

static struct bbdd_bpf_rb_context *
bbdd_bpf_rb_init(struct bbdd_prog *skel, struct bbdd_poll_ctx *pctx,
		 struct bbdd_nl *nl, struct bbdd_sess_dir *sdir,
		 char **error)
{
	struct bbdd_bpf_rb_context *rb_ctx;
	struct ring_buffer *rb;
	int rb_fd;
	int err;

	rb_ctx = malloc(sizeof(*rb_ctx));
	if (rb_ctx == NULL) {
		bbdd_util_fmterr(error, "bbdd_bpf_rb_setup: %m");
		return NULL;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.bbdd_bpf_rb),
			      bbdd_bpf_rb_handle, rb_ctx, NULL);
	if (!rb) {
		bbdd_util_fmterr(error, "ring_buffer__new: %m");
		goto free_ctx;
	}

	rb_fd = ring_buffer__epoll_fd(rb);
	err = bbdd_poll_push_fd(pctx, rb_fd, POLLIN, bbdd_bpf_rb_recv, rb_ctx,
				error);
	if (err != 0)
		goto free_ring_buffer;

	*rb_ctx = (struct bbdd_bpf_rb_context) {
		.rb = rb,
		.nl = nl,
		.sdir = sdir,
	};
	return rb_ctx;

free_ring_buffer:
	ring_buffer__free(rb);
free_ctx:
	free(rb_ctx);
	return NULL;
}

static void bbdd_bpf_rb_fini(struct bbdd_bpf_rb_context *rb_ctx)
{
	ring_buffer__free(rb_ctx->rb);
	free(rb_ctx);
}

struct bbdd_bpf *bbdd_bpf_create(struct bbdd_poll_ctx *pctx,
				 struct bbdd_nl *nl,
				 struct bbdd_bpf_global_config *conf,
				 struct bbdd_sess_dir *sdir,
				 char **error)
{
	struct bbdd_bpf *bpf;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL) {
		bbdd_util_fmterr(error, "calloc: %m");
		return NULL;
	}

	libbpf_set_print(bbdd_bpf_print);

	bpf->skel = bbdd_prog__open_and_load();
	if (!bpf->skel) {
		bbdd_util_fmterr(error, "bbdd_prog__open_and_load: %m");
		goto free_bpf;
	}

	bpf->rb_ctx = bbdd_bpf_rb_init(bpf->skel, pctx, nl, sdir, error);
	if (bpf->rb_ctx == NULL)
		goto destroy_prog;
	bpf->rb_ctx->bpf = bpf;

	return bpf;

destroy_prog:
	bbdd_prog__destroy(bpf->skel);
free_bpf:
	free(bpf);
	return NULL;
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
	bbdd_bpf_rb_fini(bpf->rb_ctx);
	bbdd_prog__destroy(bpf->skel);
	free(bpf);
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
		bbdd_util_fmterr(error, "bbdd_bpf_attach: %m");
		return NULL;
	}

	err = bpf_tc_hook_create(&hook);
	if (err) {
		bbdd_util_fmterr(error, "bpf_tc_hook_create(ifindex=%u): %s",
				 ifindex, strerror(-err));
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
		bbdd_util_fmterr(error, "bpf_tc_attach(ifindex=%u): %s",
				 ifindex, strerror(-err));
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
	bpf->rx = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_rx, ifindex,
				  BPF_TC_INGRESS, error);
	return bpf->rx != NULL ? 0 : -1;
}

int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error)
{
	bpf->skel->bss->bbdd_veth_tx_ifindex = (int)ifindex;
	bpf->tx = bbdd_bpf_attach(bpf->skel->progs.bbdd_xmit_veth_tx, ifindex,
				  BPF_TC_EGRESS, error);
	return bpf->tx != NULL ? 0 : -1;
}

static int __bbdd_bpf_session_update(struct bbdd_bpf *bpf,
				     uint32_t id,
				     uint32_t ifindex,
				     const struct bbdd_sockaddr *src,
				     const struct bbdd_sockaddr *dst,
				     uint32_t tbid,
				     uint32_t flags,
				     uint32_t min_interval_us,
				     uint32_t max_interval_us,
				     uint32_t gen_id,
				     char **error)
{
	int af = src->sa.sa_family ?: dst->sa.sa_family;
	struct bbdd_bfd_session_config config = {
		.fib_lookup = {
			.family = (uint8_t) af,
			.l4_protocol = IPPROTO_UDP,
			.sport = src->sin46.port,
			.dport = dst->sin46.port,
			.ifindex = ifindex,
			.tbid = tbid,
			.mark = gen_id,
		},
		.bpf_fib_lookup_flags = flags,
		.min_interval_us = min_interval_us,
		.max_interval_us = max_interval_us,
		.gen_id = gen_id,
	};
	int err;

	if (af != dst->sa.sa_family) {
		bbdd_util_fmterr(error, "Mismatch in families of source and destination addresses");
		return -1;
	}

	switch (af) {
	case AF_INET:
		config.fib_lookup.ipv4_src = src->sin.sin_addr.s_addr;
		config.fib_lookup.ipv4_dst = dst->sin.sin_addr.s_addr;
		break;
	case AF_INET6:
		memcpy(config.fib_lookup.ipv6_src, &src->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_src));
		memcpy(config.fib_lookup.ipv6_dst, &dst->sin6.sin6_addr,
		       sizeof(config.fib_lookup.ipv6_dst));
		break;
	default:
		bbdd_util_fmterr(error, "Unsupported session address family %d",
				 af);
		return -1;
	}

	err = bpf_map__update_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
				   &id, sizeof(id),
				   &config, sizeof(config),
				   BPF_ANY);
	if (err) {
		bbdd_util_fmterr(error, "Failed to insert / update BPF session config: %s",
				 strerror(-err));
		return -1;
	}

	return 0;
}

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    uint32_t id,
			    uint32_t ifindex,
			    const struct bbdd_sockaddr *src,
			    const struct bbdd_sockaddr *dst,
			    uint32_t tbid,
			    uint32_t flags,
			    uint32_t min_interval_us,
			    uint32_t max_interval_us,
			    uint32_t gen_id,
			    char **error)
{
	struct bbdd_bfd_session_config config;
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
				   &id, sizeof(id),
				   &config, sizeof(config), 0);
	if (err != 0) {
		bbdd_util_fmterr(error, "Failed to update session %u: session not in hash",
				 id);
		return -1;
	}

	return __bbdd_bpf_session_update(bpf,
					 id, ifindex, src, dst, tbid, flags,
					 min_interval_us, max_interval_us,
					 gen_id, error);
}

int bbdd_bpf_session_add(struct bbdd_bpf *bpf,
			 uint32_t id,
			 uint32_t ifindex,
			 const struct bbdd_sockaddr *src,
			 const struct bbdd_sockaddr *dst,
			 uint32_t tbid,
			 uint32_t flags,
			 uint32_t min_interval_us,
			 uint32_t max_interval_us,
			 uint32_t gen_id,
			 char **error)
{
	struct bbdd_bfd_session_data data = {};
	int err;

	err = __bbdd_bpf_session_update(bpf,
					id, ifindex, src, dst, tbid, flags,
					min_interval_us, max_interval_us,
					gen_id, error);
	if (err)
		return err;

	err = bpf_map__update_elem(bpf->skel->maps.bbdd_bpf_session_data_hash,
				   &id, sizeof(id),
				   &data, sizeof(data),
				   BPF_ANY);
	if (err) {
		bbdd_util_fmterr(error, "Failed to insert / update BPF session data: %s",
				 strerror(-err));
		goto delete;
	}

	return 0;

delete:
	bpf_map__delete_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
			     &id, sizeof(id), 0);
	return err;
}

int bbdd_bpf_session_delete(struct bbdd_bpf *bpf, uint32_t id,
			    char **error)
{
	int err1;
	int err2;
	int err;

	err1 = bpf_map__delete_elem(bpf->skel->maps.bbdd_bpf_session_config_hash,
				    &id, sizeof(id), 0);
	err2 = bpf_map__delete_elem(bpf->skel->maps.bbdd_bpf_session_data_hash,
				    &id, sizeof(id), 0);
	err = err1 ?: err2;

	if (err)
		bbdd_util_fmterr(error, "Failed to delete BPF session %u: %s",
				 id, strerror(-err));

	return err;
}

static void bbdd_bpf_stat_fmterr(char **error)
{
	bbdd_util_fmterr(error, "Failed to format stats to JSON: %m");
}

static int bbdd_bpf_add_stat(struct json_object *obj,
			     const char *name, uint64_t value,
			     char **error)
{
	int rc;
	rc = json_object_object_add(obj, name, json_object_new_uint64(value));
	if (rc)
		bbdd_bpf_stat_fmterr(error);
	return rc;
}

struct json_object *bbdd_bpf_global_diag_stats_json(struct bbdd_bpf *bpf,
						    char **error)
{
	struct bbdd_prog_global_diag_stats *stats;
	struct json_object *obj;

	stats = &bpf->skel->bss->bbdd_prog_global_diag_stats;

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)						\
	if (bbdd_bpf_add_stat(obj, #NAME, stats->NAME, error))	\
		goto err;

	BBDD_GLOBAL_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_bpf_session_diag_stats_json(struct bbdd_bpf *bpf,
						     uint32_t id,
						     char **error)
{
	struct bbdd_bfd_session_data data;
	struct json_object *obj;
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_bpf_session_data_hash,
				   &id, sizeof(id),
				   &data, sizeof(data), 0);
	if (err) {
		bbdd_util_fmterr(error,
				 "Failed to look up BPF session data for id %u: %s",
				 id, strerror(-err));
		return NULL;
	}

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)							\
	if (bbdd_bpf_add_stat(obj, #NAME, data.diag_stats.NAME, error))	\
		goto err;

	BBDD_SESSION_DIAG_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_bpf_session_stats_json(struct bbdd_bpf *bpf,
						uint32_t id,
						char **error)
{
	struct bbdd_bfd_session_data data;
	struct json_object *obj;
	int err;

	err = bpf_map__lookup_elem(bpf->skel->maps.bbdd_bpf_session_data_hash,
				   &id, sizeof(id),
				   &data, sizeof(data), 0);
	if (err) {
		bbdd_util_fmterr(error,
				 "Failed to look up BPF session data for id %u: %s",
				 id, strerror(-err));
		return NULL;
	}

	obj = json_object_new_object();
	if (!obj) {
		bbdd_bpf_stat_fmterr(error);
		return NULL;
	}

#define FIELD(NAME)							\
	if (bbdd_bpf_add_stat(obj, #NAME, data.stats.NAME, error))	\
		goto err;

	BBDD_SESSION_STATS(FIELD)
#undef FIELD

	return obj;

err:
	json_object_put(obj);
	return NULL;
}
