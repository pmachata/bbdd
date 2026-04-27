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

static void bbdd_util_vprinterr(char **error, const char *fmt, va_list ap)
{
	if (fmt)
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
