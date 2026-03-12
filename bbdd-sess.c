// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-sess.h"

#include <errno.h>
#include <uthash.h>

#include "bbdd.h"

/* "in uthash, your structure will never be moved or copied into another
 * location when you add it into a hash table." So it's OK to wrap the
 * structure and hand out pointers. */
struct bbdd_sess_dir_entry {
	/* key is sess.id */
	struct bbdd_d_session sess;
	UT_hash_handle hh;
};

struct bbdd_sess_dir {
	struct bbdd_sess_dir_entry *sessions;
};

struct bbdd_sess_dir *bbdd_sess_dir_create(void)
{
	struct bbdd_sess_dir *sdir;

	sdir = malloc(sizeof(*sdir));
	if (!sdir)
		return NULL;

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

struct bbdd_d_session *
bbdd_sess_dir_add_session(struct bbdd_sess_dir *sdir,
			  const struct bbdd_d_session *template)
{
	struct bbdd_sess_dir_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	*entry = (struct bbdd_sess_dir_entry) {
		.sess = *template,
	};

	HASH_ADD_INT(sdir->sessions, sess.id, entry);
	return &entry->sess;
}

struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *sdir,
						 uint32_t id)
{
	struct bbdd_sess_dir_entry *entry;

	HASH_FIND_INT(sdir->sessions, &id, entry);
	if (entry == NULL)
		return NULL;

	return &entry->sess;
}

bool bbdd_sess_dir_has_session(struct bbdd_sess_dir *sdir, uint32_t id)
{
	return bbdd_sess_dir_get_session(sdir, id) != NULL;
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
