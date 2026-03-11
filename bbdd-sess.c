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
	struct bbdd_sess_dir *dir;

	dir = malloc(sizeof(*dir));
	if (!dir)
		return NULL;

	*dir = (struct bbdd_sess_dir) {};

	return dir;
}

void bbdd_sess_dir_destroy(struct bbdd_sess_dir *dir)
{
	struct bbdd_sess_dir_entry *entry, *tmp;

	HASH_ITER(hh, dir->sessions, entry, tmp) {
		HASH_DEL(dir->sessions, entry);
		free(entry);
	}
	free(dir);
}

int bbdd_sess_dir_add_session(struct bbdd_sess_dir *dir,
			      const struct bbdd_d_session *sess)
{
	struct bbdd_sess_dir_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	*entry = (struct bbdd_sess_dir_entry) {
		.sess = *sess,
	};

	HASH_ADD_INT(dir->sessions, sess.id, entry);
	return 0;
}

struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *dir,
						 uint32_t id)
{
	struct bbdd_sess_dir_entry *entry;

	HASH_FIND_INT(dir->sessions, &id, entry);
	if (entry == NULL)
		return NULL;

	return &entry->sess;
}

int bbdd_sess_dir_del_session(struct bbdd_sess_dir *dir, uint32_t id)
{
	struct bbdd_sess_dir_entry *entry;

	HASH_FIND_INT(dir->sessions, &id, entry);
	if (entry == NULL)
		return -ENOENT;

	HASH_DEL(dir->sessions, entry);
	free(entry);
	return 0;
}
