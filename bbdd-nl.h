/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

struct bbdd_nl;

struct bbdd_nl *bbdd_nl_create(void);
void bbdd_nl_destroy(struct bbdd_nl *nl);

struct bbdd_nl_if {
	uint32_t ifindex;
	char ifname[IFNAMSIZ];
};

int bbdd_nl_list_ifs(struct bbdd_nl *nl, struct bbdd_nl_if **p_ifs,
		     size_t *p_nifs, char **error);
