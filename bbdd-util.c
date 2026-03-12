#include "bbdd-util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(strp, fmt, ap);
	va_end(ap);

	if (rc < 0)
		*strp = NULL;
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
		if (rc > 0)
			fprintf(stderr, ": ");
		fprintf(stderr, "%s\n", *error);
		free(*error);
	}
}
