// SPDX-License-Identifier: GPL-2.0+
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bbdd-prog.h"

#define FIELD(NAME) __u64 NAME;
struct bbdd_prog_stats {
	BBDD_GLOBAL_STATS(FIELD)
};
#undef FIELD

#define ETH_P_IP  0x0800          /* Internet Protocol packet     */

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define TC_ACT_REDIRECT		7

enum { NS_PER_MS = 1 * 1000 * 1000 };

volatile int bbdd_veth_tx_ifindex;
struct bbdd_prog_stats bbdd_stats;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bbdd_bfd_session_config);
	__uint(max_entries, 16 * 1024);
} bbdd_bpf_session_config_hash SEC(".maps");

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_control_packet)] = {};
	u8 udph_buf[sizeof(struct udphdr)] = {};
	u8 iph_buf[sizeof(struct iphdr)] = {};
	struct bbdd_bfd_session_config *sess;
	struct bpf_fib_lookup params = {};
	struct bbdd_bfd_control_packet *bfd;
	struct bpf_dynptr p;
	struct udphdr *udph;
	struct iphdr *iph;
	int ret;
	u32 off;
	u32 id;

	/* Filtering */
	if (skb->protocol != bpf_htons(ETH_P_IP))
		goto tx_not_bfd;

	if (bpf_dynptr_from_skb(skb, 0, &p))
		goto tx_not_bfd;

	off = sizeof(struct ethhdr);
	iph = bpf_dynptr_slice(&p, off, iph_buf, sizeof(iph_buf));
	if (!iph)
		goto tx_not_bfd;

	if (iph->protocol != IPPROTO_UDP)
		goto tx_not_bfd;

	off += sizeof(struct iphdr);
	udph = bpf_dynptr_slice(&p, off, udph_buf, sizeof(udph_buf));
	if (!udph)
		goto tx_not_bfd;

	if (udph->dest != bpf_htons(BFD_SINGLE_HOP_PORT) &&
	    udph->dest != bpf_htons(BFD_MULTI_HOP_PORT))
		goto tx_not_bfd;

	off += sizeof(*udph);
	bfd = bpf_dynptr_slice(&p, off, bfd_buf, sizeof(bfd_buf));
	if (!bfd)
		goto out;

	id = bpf_ntohl(bfd->local_id);
	sess = bpf_map_lookup_elem(&bbdd_bpf_session_config_hash, &id);
	if (!sess)
		goto tx_no_session;

	if (!skb->hash)
		bpf_set_hash(skb, id);

out:
	skb->tstamp = bpf_ktime_get_ns() + 300 * NS_PER_MS;
	return TC_ACT_OK;

tx_not_bfd:
	__sync_fetch_and_add(&bbdd_stats.tx_not_bfd, 1);
	return TC_ACT_SHOT;

tx_no_session:
	__sync_fetch_and_add(&bbdd_stats.tx_no_session, 1);
	return TC_ACT_SHOT;
}

SEC("tc")
int bbdd_rx(struct __sk_buff *skb)
{
	return bpf_redirect(bbdd_veth_tx_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
