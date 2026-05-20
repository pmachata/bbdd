/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdint.h>

#include "bbdd-flag.h"

#include "bbdd-d.i"

#define BBDD_SESS_FLAGS(X)		\
	X(MULTIHOP, multihop)		\
	X(CBIT, cbit)			\
	X(PASSIVE, passive)		\
	X(SHUTDOWN, shutdown)		\
	/**/

#define BBDD_SESS_EXPAND_ENUM(NAME, name, ...)	\
	bbdd_sess_flag_ ## name,
#define BBDD_SESS_EXPAND_PLUS1(...) + 1

enum bbdd_sess_flag_ix {
	BBDD_SESS_FLAGS(BBDD_SESS_EXPAND_ENUM)
};

enum {
	bbdd_sess_nflags =
		BBDD_SESS_FLAGS(BBDD_SESS_EXPAND_PLUS1)
};

#undef BBDD_SESS_EXPAND_PLUS1
#undef BBDD_SESS_EXPAND_ENUM

#define BBDD_SESS_EXPAND_FIELD(NAME, name, ...)	\
	struct bbdd_flag name;

struct bbdd_sess_flags {
	union {
		struct bbdd_flag flags[bbdd_sess_nflags];
		struct {
			BBDD_SESS_FLAGS(BBDD_SESS_EXPAND_FIELD)
		};
	};
};

#undef BBDD_SESS_EXPAND_FIELD

const char *bbdd_sess_flag_name(enum bbdd_sess_flag_ix flag);

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
