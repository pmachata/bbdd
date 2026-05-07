#include "bbdd-util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "bbdd.h"

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

static int bbdd_util_vwraperr(char **strp, const char *fmt, va_list ap)
{
	char *new_strp = NULL;
	int rc;

	rc = bbdd_util_vfmterr(&new_strp, fmt, ap);
	if (rc >= 0) {
		free(*strp);
		*strp = new_strp;
	}

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_wraperr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vwraperr(strp, fmt, ap);
	va_end(ap);

	return rc;
}

__attribute__((format(printf, 2, 3)))
int bbdd_util_appenderr(char **error, const char *fmt, ...)
{
	char *msg;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = bbdd_util_vfmterr(&msg, fmt, ap);
	va_end(ap);

	if (rc < 0)
		return rc;

	if (*error != NULL)
		rc = bbdd_util_wraperr(&msg, "%s: %s", msg, *error);

	/* When the wraperr call fails, we are left with just the fmt message.
	 * But that seems like the more important message to have. A low-level
	 * error is arguably worth less than where the error happened. */
	free(*error);
	*error = msg;
	return rc;
}

static void bbdd_util_vprinterr(char **error, const char *fmt, va_list ap)
{
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);

	if (*error) {
		fprintf(stderr, ": %s\n", *error);
		free(*error);
	}
}

__attribute__((format(printf, 2, 3)))
void bbdd_util_verberr(char **error, const char *fmt, ...)
{
	va_list ap;

	if (bbdd_env.verbosity <= 0) {
		free(*error);
		return;
	}

	va_start(ap, fmt);
	bbdd_util_vprinterr(error, fmt, ap);
	va_end(ap);
}

__attribute__((format(printf, 2, 3)))
void bbdd_util_printerr(char **error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bbdd_util_vprinterr(error, fmt, ap);
	va_end(ap);
}

int bbdd_util_pickerr(int rc1, char **error1, int rc2, char **error2)
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

int bbdd_util_jrpc_send(struct bbdd_sock *sock, struct json_object *obj)
{
	const char *str;
	size_t len;
	ssize_t rc;

	str = json_object_to_json_string(obj);
	if (str == NULL)
		return -1;

	len = strlen(str);
	rc = sendto(sock->fd, str, len, 0,
		    (struct sockaddr *) &sock->sa, sock->sa.len);
	if (rc < 0)
		return -1;
	return (size_t)rc == len ? 0 : -1;
}
