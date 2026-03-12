/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

__attribute__((format(printf, 2, 3)))
int bbdd_util_fmterr(char **strp, const char *fmt, ...);
