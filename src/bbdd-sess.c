// SPDX-License-Identifier: GPL-2.0
#include "bbdd-sess.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <uthash.h>
#include <utlist.h>
#include <sys/random.h>

#include "bbdd-d.h"
#include "bbdd-err.h"
#include "bbdd-sock.h"
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

/* A raw binary uthash key, zeroed before use so that padding doesn't leak
 * uninitialized bytes into the hash/comparison. */
struct bbdd_sess_dst_key {
	bool multihop;
	uint32_t table;
	sa_family_t family;
	union {
		struct in_addr  in;
		struct in6_addr in6;
	} addr;
};

/* Sessions sharing a (multihop, vrf_table, dst) key, i.e. candidates for a
 * given discr-0 packet's digest. Several sessions can legitimately share a
 * key (e.g. the same peer monitored over multiple local interfaces), so the
 * hash maps to a bucket of members rather than to a session directly. */
struct bbdd_sess_dst_bucket {
	struct bbdd_sess_dst_key key;
	struct bbdd_sess_dir_entry *members; /* DList */
	UT_hash_handle hh;
};

/* "in uthash, your structure will never be moved or copied into another
 * location when you add it into a hash table." So it's OK to wrap the
 * structure and hand out pointers. */
struct bbdd_sess_dir_entry {
	/* key is sess.local.discr */
	struct bbdd_d_session sess;
	UT_hash_handle hh;

	/* Membership in a bbdd_sess_dst_bucket's member DList, keyed by
	 * (multihop, vrf_table, dst). NULL when not indexed, e.g. between
	 * bbdd_sess_dir_add_session() and the dst being set. */
	struct bbdd_sess_dst_bucket *dst_bucket;
	struct bbdd_sess_dir_entry *prev;
	struct bbdd_sess_dir_entry *next;
};

struct bbdd_sess_dir {
	struct bbdd_sess_dir_entry *sessions;
	struct bbdd_sess_dst_bucket *dst_buckets;

	/* A spare bucket set aside by bbdd_sess_dir_dst_reserve(), so that
	 * bbdd_sess_dir_dst_index() never needs to allocate and so can't
	 * fail. NULL when nothing is reserved. */
	struct bbdd_sess_dst_bucket *dst_spare;
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
	struct bbdd_sess_dst_bucket *bucket, *btmp;
	struct bbdd_sess_dir_entry *entry, *tmp;

	free(sdir->dst_spare);

	/* Buckets just reference entries, so no need to unlink from them
	 * individually; just drop both hashes. */
	HASH_ITER(hh, sdir->dst_buckets, bucket, btmp) {
		HASH_DEL(sdir->dst_buckets, bucket);
		free(bucket);
	}

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

	bbdd_sess_dir_dst_unindex(sdir, dsess);
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

static void bbdd_sess_dst_key_init(struct bbdd_sess_dst_key *key,
				   bool multihop, uint32_t table,
				   const struct bbdd_sockaddr *addr)
{
	memset(key, 0, sizeof(*key));
	key->multihop = multihop;
	key->table = table;
	key->family = addr->sa.sa_family;

	switch (key->family) {
	case AF_INET:
		key->addr.in = addr->sin.sin_addr;
		break;
	case AF_INET6:
		key->addr.in6 = addr->sin6.sin6_addr;
		break;
	default:
		/* Callers are expected to only index/look up sessions with a
		 * real dst address. */
		assert(false);
	}
}

void bbdd_sess_dir_dst_unindex(struct bbdd_sess_dir *sdir,
			       struct bbdd_d_session *dsess)
{
	struct bbdd_sess_dir_entry *entry = (struct bbdd_sess_dir_entry *)dsess;
	struct bbdd_sess_dst_bucket *bucket = entry->dst_bucket;

	if (bucket == NULL)
		return;

	DL_DELETE(bucket->members, entry);
	entry->dst_bucket = NULL;

	if (bucket->members == NULL) {
		HASH_DEL(sdir->dst_buckets, bucket);
		free(bucket);
	}
}

struct bbdd_sess_dst_bucket *bbdd_sess_dir_dst_reserve(struct bbdd_sess_dir *sdir,
						       char **error)
{
	struct bbdd_sess_dst_bucket *bucket;

	if (sdir->dst_spare != NULL) {
		bucket = sdir->dst_spare;
		sdir->dst_spare = NULL;
		return bucket;
	}

	bucket = malloc(sizeof(*bucket));
	if (bucket == NULL)
		bbdd_err_fmt(error, "Failed to reserve dst bucket: %m");
	return bucket;
}

void bbdd_sess_dir_dst_index(struct bbdd_sess_dir *sdir,
			     struct bbdd_d_session *dsess,
			     struct bbdd_sess_dst_bucket *reserved)
{
	struct bbdd_sess_dir_entry *entry = (struct bbdd_sess_dir_entry *)dsess;
	struct bbdd_sess_dst_bucket *bucket;
	struct bbdd_sess_dst_key key;

	assert(entry->dst_bucket == NULL);
	assert(dsess->dst.sa.sa_family != 0);
	assert(reserved != NULL);

	bbdd_sess_dst_key_init(&key, dsess->local.flags.multihop,
			       dsess->vrf_table, &dsess->dst);

	HASH_FIND(hh, sdir->dst_buckets, &key, sizeof(key), bucket);
	if (bucket == NULL) {
		bucket = reserved;
		*bucket = (struct bbdd_sess_dst_bucket) { .key = key };
		HASH_ADD(hh, sdir->dst_buckets, key, sizeof(key), bucket);
	} else {
		/* Didn't need the reservation after all -- park it for next
		 * time instead of freeing it. */
		assert(sdir->dst_spare == NULL);
		sdir->dst_spare = reserved;
	}

	DL_APPEND(bucket->members, entry);
	entry->dst_bucket = bucket;
}

struct bbdd_d_session *bbdd_sess_dir_dst_first(struct bbdd_sess_dir *sdir,
					       bool multihop, uint32_t table,
					       const struct bbdd_sockaddr *addr)
{
	struct bbdd_sess_dst_bucket *bucket;
	struct bbdd_sess_dst_key key;

	bbdd_sess_dst_key_init(&key, multihop, table, addr);

	HASH_FIND(hh, sdir->dst_buckets, &key, sizeof(key), bucket);
	if (bucket == NULL)
		return NULL;

	return &bucket->members->sess;
}

struct bbdd_d_session *bbdd_sess_dir_dst_next(struct bbdd_d_session *dsess)
{
	struct bbdd_sess_dir_entry *entry = (struct bbdd_sess_dir_entry *)dsess;

	return bbdd_sess_iter_step(entry->next);
}
