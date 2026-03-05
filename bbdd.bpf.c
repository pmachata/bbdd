// SPDX-License-Identifier: GPL-2.0+
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

enum { NS_PER_MS = 1 * 1000 * 1000 };

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
