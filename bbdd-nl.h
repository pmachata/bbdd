/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdint.h>

#include "bbdd-sock.h"

struct bbdd_nl;

struct bbdd_nl *bbdd_nl_create(void);
void bbdd_nl_destroy(struct bbdd_nl *nl);

int bbdd_nl_add_veth(struct bbdd_nl *nl,
		     const char *name, uint32_t *ifindex,
		     const char *peer_name, uint32_t *peer_ifindex,
		     unsigned int nqueues,
		     char **error);

int bbdd_nl_del_if(struct bbdd_nl *nl, const char *name, char **error);
int bbdd_nl_set_if_up(struct bbdd_nl *nl, uint32_t ifindex, char **error);

int bbdd_nl_add_qdisc(struct bbdd_nl *nl,
		      uint32_t ifindex, uint32_t parent,
		      uint16_t handle, const char *kind, char **error);

uint32_t bbdd_nl_tc_h_root(void);

struct bbdd_nl_ifinfo {
	uint32_t master;
	uint32_t table;
};

int bbdd_nl_get_ifinfo(struct bbdd_nl *nl, uint32_t ifindex,
		       struct bbdd_nl_ifinfo *info, char **error);

int bbdd_nl_get_vrf_table(struct bbdd_nl *nl, uint32_t ifindex,
			  uint32_t *table, char **error);

int bbdd_nl_get_l3_master(struct bbdd_nl *nl, uint32_t ifindex,
			  uint32_t *table, char **error);

int bbdd_nl_refresh_neigh(struct bbdd_nl *nl, uint32_t ifindex,
			  const struct bbdd_sockaddr *addr, char **error);
