// SPDX-License-Identifier: GPL-2.0+
#include "bbdd-sb.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bbdd-err.h"

#define BBDD_SB_MIN_SIZE 1024

void bbdd_sb_fini(struct bbdd_sb *sb)
{
	free(sb->buf);
}

const void *bbdd_sb_buf(const struct bbdd_sb *sb)
{
	return sb->buf + sb->off;
}

const char *bbdd_sb_cstr(const struct bbdd_sb *sb)
{
	return bbdd_sb_buf(sb);
}

size_t bbdd_sb_len(const struct bbdd_sb *sb)
{
	return sb->len;
}

static void bbdd_sb_compact(struct bbdd_sb *sb)
{
	if (sb->off == 0)
		return;

	memmove(sb->buf, sb->buf + sb->off, sb->len);
	sb->off = 0;
}

static size_t bbdd_sb_end(const struct bbdd_sb *sb)
{
	return sb->off + sb->len;
}

static size_t bbdd_sb_free_tail(const struct bbdd_sb *sb)
{
	return sb->size - bbdd_sb_end(sb);
}

static char *bbdd_sb_get_buffer(struct bbdd_sb *sb, size_t extra_len,
				char **error)
{
	size_t needed_size;
	size_t nsize;
	void *nbuf;

	if (sb->buf == NULL)
		goto realloc;

	if (bbdd_sb_free_tail(sb) >= extra_len)
		return sb->buf + bbdd_sb_end(sb);

	bbdd_sb_compact(sb);

	if (bbdd_sb_free_tail(sb) >= extra_len)
		return sb->buf + bbdd_sb_end(sb);

realloc:
	assert(sb->off == 0);

	needed_size = sb->len + extra_len;
	for (nsize = sb->size; nsize < needed_size;
	     nsize = nsize > 0 ? nsize * 2 : BBDD_SB_MIN_SIZE)
		;
	if (sb->maxsize != 0 && nsize > sb->maxsize) {
		nsize = sb->maxsize;

		if (nsize < needed_size) {
			bbdd_err_fmt(error, "Buffer overflow: bytes needed %zu, allowed %zu",
				     needed_size, sb->maxsize);
			return NULL;
		}
	}

	nbuf = realloc(sb->buf, nsize);
	if (nbuf == NULL) {
		bbdd_err_fmt(error, "Cannot allocate buffer of %zu bytes: %m",
			     nsize);
		return NULL;
	}

	sb->buf = nbuf;
	sb->size = nsize;

	assert(bbdd_sb_free_tail(sb) >= extra_len);
	return sb->buf + bbdd_sb_end(sb);
}

int bbdd_sb_push_len(struct bbdd_sb *sb, const char *buf, size_t len,
		     char **error)
{
	char *space;

	space = bbdd_sb_get_buffer(sb, len + 1, error);
	if (space == NULL)
		return -ENOMEM;

	space = mempcpy(space, buf, len);
	space[0] = '\0';

	sb->len += len;
	return 0;
}

int bbdd_sb_push(struct bbdd_sb *sb, const char *str, char **error)
{
	return bbdd_sb_push_len(sb, str, strlen(str), error);
}

void bbdd_sb_pull(struct bbdd_sb *sb, size_t len)
{
	assert(len <= sb->len);
	sb->off += len;
	sb->len -= len;
}
