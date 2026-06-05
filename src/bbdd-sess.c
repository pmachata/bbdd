// SPDX-License-Identifier: GPL-2.0
#include "bbdd-sess.h"

#include <errno.h>

#include <uthash.h>
#include <sys/random.h>

#include "bbdd-d.h"
#include "bbdd-err.h"
#include "bbdd-util.h"

#define BBDD_SESS_EXPAND_NAME_STR(NAME, name, ...)	#name,
static const char *bbdd_sess_flag_names[] = {
	BBDD_SESS_FLAGS(BBDD_SESS_EXPAND_NAME_STR)
};
#undef BBDD_SESS_EXPAND_NAME_STR

const char *
bbdd_sess_flag_name(enum bbdd_sess_flag_ix flag)
{
	return bbdd_sess_flag_names[flag];
}

/* "in uthash, your structure will never be moved or copied into another
 * location when you add it into a hash table." So it's OK to wrap the
 * structure and hand out pointers. */
struct bbdd_sess_dir_entry {
	/* key is sess.local.discr */
	struct bbdd_d_session sess;
	UT_hash_handle hh;
};

struct bbdd_sess_dir {
	struct bbdd_sess_dir_entry *sessions;
};

struct bbdd_sess_dir *bbdd_sess_dir_create(char **error)
{
	struct bbdd_sess_dir *sdir;

	sdir = malloc(sizeof(*sdir));
	if (!sdir) {
		bbdd_err_fmt(error, "Failed to create session directory: %m");
		return NULL;
	}

	*sdir = (struct bbdd_sess_dir) {};
	return sdir;
}

void bbdd_sess_dir_destroy(struct bbdd_sess_dir *sdir)
{
	struct bbdd_sess_dir_entry *entry, *tmp;

	HASH_ITER(hh, sdir->sessions, entry, tmp) {
		HASH_DEL(sdir->sessions, entry);
		free(entry);
	}
	free(sdir);
}

static uint32_t bbdd_sess_rand_u32(void)
{
	uint32_t buf;
	ssize_t err;

	do {
		err = getrandom(&buf, sizeof(buf), 0);
	} while (err != sizeof(buf));

	return buf;
}

uint32_t bbdd_sess_get_unique_discr(struct bbdd_sess_dir *sdir)
{
	uint32_t discr;

	do {
		discr = bbdd_sess_rand_u32();
	} while (discr != 0 &&
		 bbdd_sess_dir_get_session(sdir, discr) != NULL);

	return discr;
}

struct bbdd_d_session *
bbdd_sess_dir_add_session(struct bbdd_sess_dir *sdir, uint32_t discr)
{
	struct bbdd_sess_dir_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	*entry = (struct bbdd_sess_dir_entry) {
		.sess.local.discr = discr,
	};

	HASH_ADD_INT(sdir->sessions, sess.local.discr, entry);
	return &entry->sess;
}

struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *sdir,
						 uint32_t discr)
{
	struct bbdd_sess_dir_entry *entry;

	HASH_FIND_INT(sdir->sessions, &discr, entry);
	if (entry == NULL)
		return NULL;

	return &entry->sess;
}

bool bbdd_sess_dir_has_session(struct bbdd_sess_dir *sdir, uint32_t discr)
{
	return bbdd_sess_dir_get_session(sdir, discr) != NULL;
}

void bbdd_sess_dir_del_session(struct bbdd_sess_dir *sdir,
			       struct bbdd_d_session *dsess)
{
	struct bbdd_sess_dir_entry *entry = (struct bbdd_sess_dir_entry *)dsess;

	HASH_DEL(sdir->sessions, entry);
	free(entry);
}

static struct bbdd_d_session *
bbdd_sess_iter_step(struct bbdd_sess_dir_entry *entry)
{
	if (entry)
		return &entry->sess;
	return NULL;
}

struct bbdd_d_session *bbdd_sess_iter_start(struct bbdd_sess_dir *sdir)
{
	return bbdd_sess_iter_step(sdir->sessions);
}

struct bbdd_d_session *bbdd_sess_iter_next(struct bbdd_d_session *dsess)
{
	struct bbdd_sess_dir_entry *entry = (struct bbdd_sess_dir_entry *)dsess;

	return bbdd_sess_iter_step(entry->hh.next);
}
