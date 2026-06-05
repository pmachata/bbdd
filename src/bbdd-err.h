/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdarg.h>

int bbdd_err_vfmt(char **strp, const char *fmt, va_list ap);

/* Format an error into *strp. *strp is initialized to NULL on out of
 * memory conditions, so it is in a well-defined state after the call. The
 * incoming value of *strp can be uninitialized. */
__attribute__((format(printf, 2, 3)))
int bbdd_err_fmt(char **strp, const char *fmt, ...);

/* Given a valid string in *strp, form a new string, free *strp, and put
 * the new string there. fmt can therefore reference *strp itself. Leaves
 * *strp intact on out of memory conditions. */
__attribute__((format(printf, 2, 3)))
int bbdd_err_wrap(char **strp, const char *fmt, ...);

/* Formats the given message. Then when *error is non-NULL, it appends a
 * ": $error" afterwards. Puts the resulting pointer back to *error. */
__attribute__((format(printf, 2, 3)))
int bbdd_err_app(char **error, const char *fmt, ...);

/* Prints the given message. Then when *error is non-NULL, it appends a
 * ": $error" afterwards. Puts the resulting pointer back to *error. */
__attribute__((format(printf, 2, 3)))
void bbdd_err_print(char **error, const char *fmt, ...);

int bbdd_err_pick(int rc1, char **error1, int rc2, char **error2);
void bbdd_err_xfer(char **error, char **src);
