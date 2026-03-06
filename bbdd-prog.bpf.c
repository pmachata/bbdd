// SPDX-License-Identifier: GPL-2.0+
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK	0
#define TC_ACT_REDIRECT	7

enum { NS_PER_MS = 1 * 1000 * 1000 };

volatile int bbdd_veth_tx_ifindex;

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

SEC("tc")
int bbdd_rx(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
