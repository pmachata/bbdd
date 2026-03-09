/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdint.h>
#include <json-c/json_object.h>

#include "bbdd-sock.h"

struct bbdd_bpf;

struct bbdd_bpf *bbdd_bpf_create(char **error);
void bbdd_bpf_destroy(struct bbdd_bpf *bpf);

int bbdd_bpf_attach_veth_rx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);
int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);

struct json_object *bbdd_bpf_global_stats_json(struct bbdd_bpf *bpf,
					       char **error);

/* Either instert a new session, or update parameters of the existing one.
 * In the latter case, gen_id is of the existing session is bumped by 1. */
int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    uint32_t lid,
			    uint32_t ifindex,
			    const struct bbdd_sockaddr *src,
			    const struct bbdd_sockaddr *dst,
			    uint32_t tbid,
			    uint32_t flags,
			    uint64_t min_interval,
			    uint64_t max_interval,
			    char **error);

int bbdd_bpf_session_delete(struct bbdd_bpf *bpf, uint32_t lid, char **error);
