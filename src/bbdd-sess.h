/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bbdd-flag.h"

#include "bbdd-d.i"

struct bbdd_sockaddr;

#define BBDD_SESS_FLAGS(X)		\
	X(MULTIHOP, multihop)		\
	X(CPI, cpi)			\
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

struct bbdd_sess_dst_bucket;

/* Reserve a bucket token for a subsequent bbdd_sess_dir_dst_index() call, so
 * that it's guaranteed not to need to allocate and so can't fail. Returns
 * NULL on failure. The intended sequence around mutating a session's
 * dst/multihop/vrf_table (which together make up the index key) is:
 * reserve(), unindex(), mutate the session, index(reserved token). That way
 * the only fallible step happens before the mutation, instead of after. */
struct bbdd_sess_dst_bucket *bbdd_sess_dir_dst_reserve(struct bbdd_sess_dir *sdir,
						       char **error);

/* Index/unindex sess by (multihop, vrf_table, dst). sess->dst must be set
 * (family != 0), and reserved must be a token from bbdd_sess_dir_dst_reserve()
 * when indexing; reserved is either consumed, or handed back for reuse by a
 * later reserve() call. Unindexing a not-currently-indexed sess is a no-op. */
void bbdd_sess_dir_dst_index(struct bbdd_sess_dir *sdir,
			     struct bbdd_d_session *sess,
			     struct bbdd_sess_dst_bucket *reserved);
void bbdd_sess_dir_dst_unindex(struct bbdd_sess_dir *sdir,
			       struct bbdd_d_session *sess);

/* Iterate sessions indexed under (multihop, vrf_table, addr). */
struct bbdd_d_session *bbdd_sess_dir_dst_first(struct bbdd_sess_dir *sdir,
					       bool multihop, uint32_t table,
					       const struct bbdd_sockaddr *addr);
struct bbdd_d_session *bbdd_sess_dir_dst_next(struct bbdd_d_session *cur);
