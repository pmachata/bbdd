/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once
#include <stdint.h>

/* bbdd.h */
struct bbdd_d_session;

/* bbdd-sess.c */
struct bbdd_sess_dir;

struct bbdd_sess_dir *bbdd_sess_dir_create(char **error);
void bbdd_sess_dir_destroy(struct bbdd_sess_dir *sdir);

uint32_t bbdd_sess_get_unique_discr(struct bbdd_sess_dir *sdir);
struct bbdd_d_session *bbdd_sess_dir_add_session(struct bbdd_sess_dir *sdir,
						 uint32_t discr);

void bbdd_sess_dir_del_session(struct bbdd_sess_dir *sdir,
			       struct bbdd_d_session *sess);

struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *sdir,
						 uint32_t discr);
bool bbdd_sess_dir_has_session(struct bbdd_sess_dir *sdir, uint32_t discr);

struct bbdd_d_session *bbdd_sess_iter_start(struct bbdd_sess_dir *sdir);
struct bbdd_d_session *bbdd_sess_iter_next(struct bbdd_d_session *cur);
