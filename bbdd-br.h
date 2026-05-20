/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

/* bbdd-mon.c */

struct bbdd_mon_topics;

/* bbdd-br.c */

int bbdd_br_start(int argc, char **argv, const struct bbdd_mon_topics *topics);
