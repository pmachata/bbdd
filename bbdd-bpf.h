/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

struct bbdd_bpf;

struct bbdd_bpf *bbdd_bpf_create(char **error);
void bbdd_bpf_destroy(struct bbdd_bpf *bpf);
