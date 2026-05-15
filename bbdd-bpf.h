/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdint.h>
#include <json-c/json_object.h>

#include "bbdd-nl.h"
#include "bbdd-poll.h"
#include "bbdd-sess.h"
#include "bbdd-sock.h"

/* bbdd-prog.h */

struct bbdd_bpf_global_config;

/* bbdd-prog-stat.h */

struct bbdd_prog_session_data_stats;

/* bbdd-mon.c */

struct bbdd_mon;

/* bbdd-bfdd.c */

struct bbdd_bfdd;

/* bbdd-bpf.c */

struct bbdd_bpf;
struct bbdd_bpf_session;

struct bbdd_bpf_match_digest {
	uint32_t ifindex;
	uint8_t ttl;
	bool multihop;
	uint32_t table;
	struct bbdd_sockaddr src;
	struct bbdd_sockaddr dst;
};

struct bbdd_bpf_cbs {
	void *data;
	void (*session_state_changed)(struct bbdd_d_session *dsess, void *data);

	/* Returns <0 for errors, >=0 is number of matches. Returns one of the
	 * matched sessions in *ret_dsess. */
	int (*match_session)(struct bbdd_d_session **ret_dsess,
			     struct bbdd_bpf_match_digest *digest,
			     void *data,
			     char **error);

	struct bbdd_d_session *(*find_session)(uint32_t discr, void *data);
};

struct bbdd_bpf *bbdd_bpf_create(const struct bbdd_bpf_cbs *cbs,
				 struct bbdd_poll_ctx *pctx,
				 struct bbdd_nl *nl,
				 struct bbdd_bpf_global_config *conf,
				 struct bbdd_mon *mon,
				 char **error);
void bbdd_bpf_destroy(struct bbdd_bpf *bpf);

struct json_object *bbdd_bpf_global_diag_stats_json(struct bbdd_bpf *bpf,
						    char **error);

struct json_object *bbdd_bpf_session_diag_stats_json(struct bbdd_bpf *bpf,
						     uint32_t discr,
						     char **error);

struct json_object *bbdd_bpf_session_stats_json(struct bbdd_bpf *bpf,
						uint32_t discr,
						char **error);

int bbdd_bpf_session_state_json(struct bbdd_bpf *bpf, uint32_t discr,
				struct json_object *state_obj, char **error);

int bbdd_bpf_session_stats_fill(struct bbdd_bpf *bpf, uint32_t discr,
				struct bbdd_prog_session_data_stats *out,
				char **error);

int bbdd_bpf_session_add(struct bbdd_bpf *bpf,
			 const struct bbdd_d_session *dsess,
			 char **error);

int bbdd_bpf_session_activate(struct bbdd_bpf *bpf,
			      const struct bbdd_d_session *dsess,
			      char **error);

int bbdd_bpf_session_update(struct bbdd_bpf *bpf,
			    const struct bbdd_d_session *dsess,
			    char **error);

void bbdd_bpf_session_del(struct bbdd_bpf *bpf,
			  const struct bbdd_d_session *dsess);
