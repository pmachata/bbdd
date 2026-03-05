/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdint.h>

struct bbdd_bpf;

struct bbdd_bpf *bbdd_bpf_create(char **error);
void bbdd_bpf_destroy(struct bbdd_bpf *bpf);

int bbdd_bpf_attach_veth_rx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);
int bbdd_bpf_attach_veth_tx(struct bbdd_bpf *bpf, uint32_t ifindex,
			    char **error);
