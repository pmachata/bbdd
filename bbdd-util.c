#include "bbdd-util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

int bbdd_util_vfmterr(char **strp, const char *fmt, va_list ap)
{
	int rc;

	if (!strp)
		return 0;

	rc = vasprintf(strp, fmt, ap);
	if (rc < 0)
		*strp = NULL;
	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vfmterr(strp, fmt, ap);
	va_end(ap);

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_wraperr(char **strp, const char *fmt, ...)
{
	char *new_strp = NULL;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vfmterr(&new_strp, fmt, ap);
	va_end(ap);

	if (rc >= 0) {
		free(*strp);
		*strp = new_strp;
	}

	return rc;
}

__attribute__((format(printf, 3, 4)))
void bbdd_util_printerr(int rc, char **error, const char *fmt, ...)
{
	va_list ap;

	if (!rc)
		return;

	if (fmt) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	if (*error) {
		fprintf(stderr, ": %s\n", *error);
		free(*error);
	}
}
