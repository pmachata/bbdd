// SPDX-License-Identifier: GPL-2.0+
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bbdd-prog.h"

#define ETH_P_IP	0x0800          /* Internet Protocol packet */
#define ETH_P_IPV6	0x86DD          /* IPv6 over bluebook */
#define ETH_ALEN	6

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define TC_ACT_REDIRECT		7

enum { NS_PER_US = 1 * 1000 };
static const u32 uint32_max = -1U;

volatile int bbdd_veth_tx_ifindex;
struct bbdd_prog_global_diag_stats bbdd_prog_global_diag_stats;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bbdd_bfd_session_config);
	__uint(max_entries, 16 * 1024);
} bbdd_bpf_session_config_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bbdd_bfd_session_data);
	__uint(max_entries, 16 * 1024);
} bbdd_bpf_session_data_hash SEC(".maps");

static bool bbdd_tx_validate_ipv4(struct bpf_dynptr *p, u32 *off, u16 *tot_len)
{
	u8 iph_buf[sizeof(struct iphdr)];
	struct iphdr *iph;

	iph = bpf_dynptr_slice(p, *off, iph_buf, sizeof(iph_buf));
	if (!iph)
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	*tot_len = bpf_ntohs(iph->tot_len);
	*off += sizeof(struct iphdr);
	return true;
}

static bool bbdd_tx_update_ipv4(struct bpf_dynptr *p,
				struct bpf_fib_lookup *params)
{
	u8 iph_buf[sizeof(struct iphdr)];
	u32 off = sizeof(struct ethhdr);
	struct iphdr *iph;
	int ret;

	iph = bpf_dynptr_slice_rdwr(p, off, iph_buf, sizeof(iph_buf));
	if (!iph)
		return false;

	iph->saddr = params->ipv4_src;
	if (iph == (void *) iph_buf) {
		ret = bpf_dynptr_write(p, off, iph_buf, sizeof(iph_buf), 0);
		if (ret)
			return false;
	}

	return true;
}

static bool bbdd_tx_validate_ipv6(struct bpf_dynptr *p, u32 *off, u16 *tot_len)
{
	u8 ip6h_buf[sizeof(struct ipv6hdr)];
	struct ipv6hdr *ip6h;

	ip6h = bpf_dynptr_slice(p, *off, ip6h_buf, sizeof(ip6h_buf));
	if (!ip6h)
		return false;
	if (ip6h->nexthdr != IPPROTO_UDP)
		return false;

	*tot_len = bpf_ntohs(ip6h->payload_len) + sizeof(struct ipv6hdr);
	*off += sizeof(struct ipv6hdr);
	return true;
}

static bool bbdd_tx_update_ipv6(struct bpf_dynptr *p,
				struct bpf_fib_lookup *params)
{
	u8 ip6h_buf[sizeof(struct ipv6hdr)];
	u32 off = sizeof(struct ethhdr);
	struct ipv6hdr *ip6h;
	int ret;

	ip6h = bpf_dynptr_slice_rdwr(p, off, ip6h_buf, sizeof(ip6h_buf));
	if (!ip6h)
		return false;
	__builtin_memcpy(ip6h->saddr.in6_u.u6_addr32, params->ipv6_src,
			    sizeof(params->ipv6_src));
	if (ip6h == (void *) ip6h_buf) {
		ret = bpf_dynptr_write(p, off, ip6h_buf, sizeof(ip6h_buf), 0);
		if (ret)
			return false;
	}

	return true;
}

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_control_packet)] = {};
	u8 udph_buf[sizeof(struct udphdr)] = {};
	u8 eth_buf[sizeof(struct ethhdr)] = {};
	union {
		u8 ip[sizeof(struct iphdr)];
		u8 ip6[sizeof(struct ipv6hdr)];
	} ipbuf = {};
	struct bbdd_bfd_control_packet *bfd;
	struct udphdr *udph;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	struct bpf_dynptr p;
	u32 off;
	u16 proto;

	struct bbdd_bfd_session_config *config;
	struct bbdd_bfd_session_data *data;
	struct bpf_fib_lookup params;
	u64 interval_us;
	u16 tot_len;
	u32 id;

	int ret;

	/* Filtering */
	proto = skb->protocol;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		goto tx_not_bfd;

	if (bpf_dynptr_from_skb(skb, 0, &p))
		goto tx_not_bfd;

	off = sizeof(struct ethhdr);
	if (proto == bpf_htons(ETH_P_IP)) {
		if (!bbdd_tx_validate_ipv4(&p, &off, &tot_len))
			goto tx_not_bfd;
	} else {
		if (!bbdd_tx_validate_ipv6(&p, &off, &tot_len))
			goto tx_not_bfd;
	}

	udph = bpf_dynptr_slice(&p, off, udph_buf, sizeof(udph_buf));
	if (!udph)
		goto tx_not_bfd;

	if (udph->dest != bpf_htons(BFD_SINGLE_HOP_PORT) &&
	    udph->dest != bpf_htons(BFD_MULTI_HOP_PORT))
		goto tx_not_bfd;

	off += sizeof(*udph);
	bfd = bpf_dynptr_slice(&p, off, bfd_buf, sizeof(bfd_buf));
	if (!bfd)
		goto tx_not_bfd;

	id = bpf_ntohl(bfd->local_id);
	config = bpf_map_lookup_elem(&bbdd_bpf_session_config_hash, &id);
	if (config == NULL)
		goto tx_no_session;

	data = bpf_map_lookup_elem(&bbdd_bpf_session_data_hash, &id);
	if (data == NULL)
		goto tx_no_session;

	if (skb->mark != config->gen_id)
		/* Obsolete packet. */
		return TC_ACT_SHOT;

	if (!skb->hash)
		bpf_set_hash(skb, id);

#define BUMP(COUNTER) __sync_fetch_and_add(&COUNTER, 1)

	/* FIB lookup */
	params = config->fib_lookup;
	params.tot_len = tot_len;
	ret = bpf_fib_lookup(skb, &params, sizeof(params), BPF_FIB_LOOKUP_SRC);
	if (ret < 0) {
		BUMP(data->stats.fail_lookup);
		goto out;
	} else {
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			break;
		case BPF_FIB_LKUP_RET_BLACKHOLE:
			BUMP(data->stats.dst_blackholed);
			goto out;
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			BUMP(data->stats.dst_unreachable);
			goto out;
		case BPF_FIB_LKUP_RET_PROHIBIT:
			BUMP(data->stats.dst_prohibited);
			goto out;
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
			BUMP(data->stats.indev_no_forwarding);
			goto out;
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
			BUMP(data->stats.req_encap);
			goto out;
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			BUMP(data->stats.no_neighbor);
			goto out;
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			BUMP(data->stats.req_fragmentation);
			goto out;
		case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
			BUMP(data->stats.no_src_addr);
			goto out;
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			BUMP(data->stats.not_forwarded);
			goto out;
		}
	}

	eth = bpf_dynptr_slice_rdwr(&p, 0, eth_buf, sizeof(eth_buf));
	if (!eth) {
		BUMP(data->stats.fail_update);
		goto out;
	}

	__builtin_memcpy(eth->h_source, params.smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, params.dmac, ETH_ALEN);
	if (eth == (void *) eth_buf) {
		ret = bpf_dynptr_write(&p, 0, eth_buf, sizeof(eth_buf), 0);
		if (ret) {
			BUMP(data->stats.fail_update);
			goto out;
		}
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		if (!bbdd_tx_update_ipv4(&p, &params)) {
			BUMP(data->stats.fail_update);
			goto out;
		}
	} else {
		if (!bbdd_tx_update_ipv6(&p, &params)) {
			BUMP(data->stats.fail_update);
			goto out;
		}
	}

	ret = bpf_clone_redirect(skb, params.ifindex, 0);
	if (ret) {
		BUMP(data->stats.fail_redir);
		goto out;
	}

out:
	interval_us = config->max_interval_us - config->min_interval_us;
	interval_us = ((u64) bpf_get_prandom_u32()) * interval_us / uint32_max;
	interval_us += config->min_interval_us;
	skb->tstamp = bpf_ktime_get_ns() + interval_us * NS_PER_US;
	return TC_ACT_OK;

tx_not_bfd:
	BUMP(bbdd_prog_global_diag_stats.tx_not_bfd);
	return TC_ACT_SHOT;

tx_no_session:
	BUMP(bbdd_prog_global_diag_stats.tx_no_session);
	return TC_ACT_SHOT;
}

SEC("tc")
int bbdd_rx(struct __sk_buff *skb)
{
	return bpf_redirect(bbdd_veth_tx_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
