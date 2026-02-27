/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

struct bbdd_nl;

struct bbdd_nl *bbdd_nl_create(void);
void bbdd_nl_destroy(struct bbdd_nl *nl);

int bbdd_nl_list_ifs(struct bbdd_nl *nl, char **error);
