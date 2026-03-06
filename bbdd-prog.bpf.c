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

#define BFD_CONTROL_DPORT_SHOP	3784

enum { NS_PER_MS = 1 * 1000 * 1000 };

volatile int bbdd_veth_tx_ifindex;
struct bbdd_prog_stats bbdd_stats;

struct bfd_control_packet {
	__be16 vsf;	/* version, state, flags */
	u8 detect_mult;
	u8 length;
	__be32 local_id;
	__be32 remote_id;
	__be32 desired_tx;
	__be32 required_rx;
	__be32 required_echo_rx;
};

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bfd_control_packet)] = {};
	u8 udph_buf[sizeof(struct udphdr)] = {};
	u8 iph_buf[sizeof(struct iphdr)] = {};
	struct bpf_fib_lookup params = {};
	struct bfd_control_packet *bfd;
	struct bpf_dynptr p;
	struct udphdr *udph;
	struct iphdr *iph;
	int ret;
	u32 key;
	u32 off;

	/* Filtering */
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_SHOT;

	if (bpf_dynptr_from_skb(skb, 0, &p))
		return TC_ACT_SHOT;

	off = sizeof(struct ethhdr);
	iph = bpf_dynptr_slice(&p, off, iph_buf, sizeof(iph_buf));
	if (!iph)
		return TC_ACT_SHOT;

	if (iph->protocol != IPPROTO_UDP)
		return TC_ACT_SHOT;

	off += sizeof(struct iphdr);
	udph = bpf_dynptr_slice(&p, off, udph_buf, sizeof(udph_buf));
	if (!udph)
		return TC_ACT_SHOT;

	if (udph->dest != bpf_htons(BFD_CONTROL_DPORT_SHOP))
		return TC_ACT_SHOT;

	off += sizeof(*udph);
	bfd = bpf_dynptr_slice(&p, off, bfd_buf, sizeof(bfd_buf));
	if (!bfd)
		goto out;

	key = bpf_ntohl(bfd->local_id);
	if (!skb->hash)
		bpf_set_hash(skb, key);

out:
	skb->tstamp = bpf_ktime_get_ns() + 300 * NS_PER_MS;
	__sync_fetch_and_add(&bbdd_stats.packets_processed, 1);
	return TC_ACT_OK;
}

SEC("tc")
int bbdd_rx(struct __sk_buff *skb)
{
	return bpf_redirect(bbdd_veth_tx_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
