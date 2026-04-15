/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once
#include <stdarg.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

int bbdd_util_vfmterr(char **strp, const char *fmt, va_list ap);

/* Format an error into *strp. *strp is initialized to NULL on out of
 * memory conditions, so it is in a well-defined state after the call. The
 * incoming value of *strp can be uninitialized. */
__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...);

/* Given a valid string in *strp, form a new string, free *strp, and put
 * the new string there. fmt can therefore reference *strp itself. Leaves
 * *strp intact on out of memory conditions. */
__attribute__((format(printf, 2, 3)))
int bbdd_util_wraperr(char **strp, const char *fmt, ...);

/* If rc != 0, *error shall be a valid error string, which is printed out
 * and freed. A nop when rc == 0. */
__attribute__((format(printf, 3, 4)))
void bbdd_util_printerr(int rc, char **error, const char *fmt, ...);
