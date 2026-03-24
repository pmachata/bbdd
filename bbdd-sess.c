// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-sess.h"

#include <errno.h>
#include <uthash.h>
#include <sys/random.h>

#include "bbdd.h"

/* "in uthash, your structure will never be moved or copied into another
 * location when you add it into a hash table." So it's OK to wrap the
 * structure and hand out pointers. */
struct bbdd_sess_dir_entry {
	/* key is sess.local.descr */
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

static uint32_t bbdd_sess_rand_u32(void)
{
	uint32_t buf;
	ssize_t err;

	do {
		err = getrandom(&buf, sizeof(buf), 0);
	} while (err != sizeof(buf));

	return buf;
}

uint32_t bbdd_sess_get_unique_descr(struct bbdd_sess_dir *sdir)
{
	uint32_t descr;

	do {
		descr = bbdd_sess_rand_u32();
	} while (descr != 0 &&
		 bbdd_sess_dir_get_session(sdir, descr) != NULL);

	return descr;
}

struct bbdd_d_session *
bbdd_sess_dir_add_session(struct bbdd_sess_dir *sdir, uint32_t descr)
{
	struct bbdd_sess_dir_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	*entry = (struct bbdd_sess_dir_entry) {
		.sess.local.descr = descr,
	};

	HASH_ADD_INT(sdir->sessions, sess.local.descr, entry);
	return &entry->sess;
}

struct bbdd_d_session *bbdd_sess_dir_get_session(struct bbdd_sess_dir *sdir,
						 uint32_t descr)
{
	struct bbdd_sess_dir_entry *entry;

	HASH_FIND_INT(sdir->sessions, &descr, entry);
	if (entry == NULL)
		return NULL;

	return &entry->sess;
}

bool bbdd_sess_dir_has_session(struct bbdd_sess_dir *sdir, uint32_t descr)
{
	return bbdd_sess_dir_get_session(sdir, descr) != NULL;
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
