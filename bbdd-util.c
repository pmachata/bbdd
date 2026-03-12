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
