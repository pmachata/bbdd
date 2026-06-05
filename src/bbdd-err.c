// SPDX-License-Identifier: GPL-2.0
#include "bbdd-err.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int bbdd_err_verbosity;

int bbdd_err_vfmt(char **strp, const char *fmt, va_list ap)
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
int bbdd_err_fmt(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_err_vfmt(strp, fmt, ap);
	va_end(ap);

	return rc;
}

static int bbdd_err_vwraperr(char **strp, const char *fmt, va_list ap)
{
	char *new_strp = NULL;
	int rc;

	rc = bbdd_err_vfmt(&new_strp, fmt, ap);
	if (rc >= 0) {
		free(*strp);
		*strp = new_strp;
	}

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_err_wrap(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_err_vwraperr(strp, fmt, ap);
	va_end(ap);

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_err_app(char **error, const char *fmt, ...)
{
	char *msg;
	va_list ap;
	int rc;

	if (error == NULL)
		return 0;

	va_start(ap, fmt);
	rc = bbdd_err_vfmt(&msg, fmt, ap);
	va_end(ap);

	if (rc < 0)
		return rc;

	if (*error != NULL)
		rc = bbdd_err_wrap(&msg, "%s: %s", msg, *error);

	/* When the wraperr call fails, we are left with just the fmt message.
	 * But that seems like the more important message to have. A low-level
	 * error is arguably worth less than where the error happened. */
	free(*error);
	*error = msg;
	return rc;
}

static void bbdd_err_vprinterr(char **error, const char *fmt, va_list ap)
{
	if (bbdd_err_verbosity < 0)
		return;

	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);

	if (*error) {
		fprintf(stderr, "%s%s\n",
			fmt != NULL ? ": " : "", *error);
		free(*error);
	}
}

__attribute__((format(printf, 2, 3)))
void bbdd_err_print(char **error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bbdd_err_vprinterr(error, fmt, ap);
	va_end(ap);
}

int bbdd_err_pick(int rc1, char **error1, int rc2, char **error2)
{
	if (rc1 == 0 && rc2 == 0)
		return 0;

	if (rc1 != 0 && rc2 != 0) {
		free(*error2);
		*error2 = NULL;
		return rc1;
	}

	if (rc2 != 0) {
		*error1 = *error2;
		*error2 = NULL;
		return rc2;
	}

	return rc1;
}

void bbdd_err_xfer(char **error, char **src)
{
	if (error == NULL)
		return;
	*error = *src;
	*src = NULL;
}

