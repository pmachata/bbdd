/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once
#include <stdint.h>

/* bbdd.h */
struct bbdd_d_session;

/* bbdd-sess.c */
struct bbdd_sess_dir;

struct bbdd_sess_dir *bbdd_sess_dir_create(void);
void bbdd_sess_dir_destroy(struct bbdd_sess_dir *dir);
int bbdd_sess_dir_add_session(struct bbdd_sess_dir *dir,
			      const struct bbdd_d_session *sess);
struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *dir,
						 uint32_t id);
int bbdd_sess_dir_del_session(struct bbdd_sess_dir *dir, uint32_t id);
