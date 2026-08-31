/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stddef.h>

struct bbdd_sb {
	void *buf;
	size_t off;   /* Message start. */
	size_t len;   /* Message length. */
	size_t size;  /* The allocated size.  */
	size_t maxsize; /* Maximum allowed size. 0 for no limit. */
};

void bbdd_sb_fini(struct bbdd_sb *sb);

const char *bbdd_sb_cstr(const struct bbdd_sb *sb);
const void *bbdd_sb_buf(const struct bbdd_sb *sb);
size_t bbdd_sb_len(const struct bbdd_sb *sb);

int bbdd_sb_push(struct bbdd_sb *sb, const char *str, char **error);
int bbdd_sb_push_len(struct bbdd_sb *sb, const char *buf, size_t len,
		     char **error);

void bbdd_sb_pull(struct bbdd_sb *sb, size_t len);
