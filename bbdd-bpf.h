/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdint.h>
#include <json-c/json_object.h>

#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-sess.h"
#include "bbdd-sock.h"

struct bbdd_bpf;
struct bbdd_bpf_global_config;

struct bbdd_bpf *bbdd_bpf_create(struct bbdd_poll_ctx *pctx,
				 struct bbdd_nl *nl,
				 struct bbdd_bpf_global_config *conf,
				 struct bbdd_sess_dir *sdir,
				 char **error);
void bbdd_bpf_destroy(struct bbdd_bpf *bpf);

int bbdd_bpf_attach_veth_rx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);
int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);

struct json_object *bbdd_bpf_global_diag_stats_json(struct bbdd_bpf *bpf,
						    char **error);

struct json_object *bbdd_bpf_session_diag_stats_json(struct bbdd_bpf *bpf,
						     uint32_t id,
						     char **error);

struct json_object *bbdd_bpf_session_stats_json(struct bbdd_bpf *bpf,
						uint32_t id,
						char **error);

int bbdd_bpf_session_delete(struct bbdd_bpf *bpf, uint32_t lid, char **error);

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    const struct bbdd_d_session *dsess,
			    uint32_t veth_tx_ifindex,
			    bool add, char **error);
