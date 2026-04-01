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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} bbdd_bpf_rb SEC(".maps");

static void bbdd_tx_notify_no_neighbor(u16 proto,
				       const struct bpf_fib_lookup *params)
{
	struct bbdd_bpf_rb_elem_tx_no_neighbor *elem;

	elem = bpf_ringbuf_reserve(&bbdd_bpf_rb, sizeof(*elem), 0);
	if (!elem)
		return;

	elem->head.type = BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR;
	elem->ifindex = params->ifindex;
	elem->ethtype = bpf_ntohs(proto);
	if (proto == bpf_htons(ETH_P_IP))
		elem->addr.addr[0] = params->ipv4_dst;
	else
		__builtin_memcpy(elem->addr.addr, params->ipv6_dst,
				 sizeof(elem->addr.addr));
	bpf_ringbuf_submit(elem, 0);
}

static bool bbdd_is_bfd_ipv4(struct bpf_dynptr *p, u32 *off, u16 *tot_len)
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

static bool bbdd_is_bfd_ipv6(struct bpf_dynptr *p, u32 *off, u16 *tot_len)
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

static struct bbdd_bfd_control_packet *
bbdd_get_bfd(struct __sk_buff *skb, u16 *tot_len,
	     u8 *bfd_buf, size_t bfd_buf_size)
{
	u8 udph_buf[sizeof(struct udphdr)] = {};
	u16 proto = skb->protocol;
	struct bpf_dynptr p;
	struct udphdr *udph;
	u32 off;

	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return NULL;

	if (bpf_dynptr_from_skb(skb, 0, &p))
		return NULL;

	off = sizeof(struct ethhdr);
	if (proto == bpf_htons(ETH_P_IP)) {
		if (!bbdd_is_bfd_ipv4(&p, &off, tot_len))
			return NULL;
	} else {
		if (!bbdd_is_bfd_ipv6(&p, &off, tot_len))
			return NULL;
	}

	udph = bpf_dynptr_slice(&p, off, udph_buf, sizeof(udph_buf));
	if (!udph)
		return NULL;

	if (udph->dest != bpf_htons(BFD_SINGLE_HOP_PORT) &&
	    udph->dest != bpf_htons(BFD_MULTI_HOP_PORT))
		return NULL;

	off += sizeof(*udph);
	return bpf_dynptr_slice(&p, off, bfd_buf, bfd_buf_size);
}

static bool bbdd_tx_update_ipv4(struct __sk_buff *skb, struct bpf_dynptr *p,
				const struct bpf_fib_lookup *params)
{
	u8 iph_buf[sizeof(struct iphdr)];
	u32 ip_off = sizeof(struct ethhdr);
	struct iphdr *iph;
	__be32 old_saddr;
	int ret;

	iph = bpf_dynptr_slice_rdwr(p, ip_off, iph_buf, sizeof(iph_buf));
	if (!iph)
		return false;

	old_saddr = iph->saddr;
	iph->saddr = params->ipv4_src;
	if (iph == (void *) iph_buf) {
		ret = bpf_dynptr_write(p, ip_off, iph_buf, sizeof(iph_buf), 0);
		if (ret)
			return false;
	}

	ret = bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
				  old_saddr, params->ipv4_src, sizeof(__be32));
	if (ret)
		return false;

	/* BPF_F_MARK_MANGLED_0 skips the update when the checksum field is 0,
	 * which is the IPv4 UDP "checksum disabled" convention. */
	ret = bpf_l4_csum_replace(skb,
				  ip_off + sizeof(struct iphdr) +
				  offsetof(struct udphdr, check),
				  old_saddr, params->ipv4_src,
				  BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
				  sizeof(__be32));
	return !ret;
}

static bool bbdd_tx_update_ipv6(struct __sk_buff *skb, struct bpf_dynptr *p,
				const struct bpf_fib_lookup *params)
{
	u8 ip6h_buf[sizeof(struct ipv6hdr)];
	u32 ip6_off = sizeof(struct ethhdr);
	u32 udp_csum_off = ip6_off + sizeof(struct ipv6hdr) +
			   offsetof(struct udphdr, check);
	struct ipv6hdr *ip6h;
	__be32 old_src[4];
	int ret;

	ip6h = bpf_dynptr_slice_rdwr(p, ip6_off, ip6h_buf, sizeof(ip6h_buf));
	if (!ip6h)
		return false;

	__builtin_memcpy(old_src, ip6h->saddr.in6_u.u6_addr32, sizeof(old_src));
	__builtin_memcpy(ip6h->saddr.in6_u.u6_addr32, params->ipv6_src,
			 sizeof(params->ipv6_src));
	if (ip6h == (void *) ip6h_buf) {
		ret = bpf_dynptr_write(p, ip6_off, ip6h_buf, sizeof(ip6h_buf), 0);
		if (ret)
			return false;
	}

	/* IPv6 has no IP header checksum. Update the UDP checksum
	 * incrementally for each 4-byte word of the changed source address. */
	if (bpf_l4_csum_replace(skb, udp_csum_off,
				old_src[0], params->ipv6_src[0],
				BPF_F_PSEUDO_HDR | sizeof(__be32)) ||
	    bpf_l4_csum_replace(skb, udp_csum_off,
				old_src[1], params->ipv6_src[1],
				BPF_F_PSEUDO_HDR | sizeof(__be32)) ||
	    bpf_l4_csum_replace(skb, udp_csum_off,
				old_src[2], params->ipv6_src[2],
				BPF_F_PSEUDO_HDR | sizeof(__be32)) ||
	    bpf_l4_csum_replace(skb, udp_csum_off,
				old_src[3], params->ipv6_src[3],
				BPF_F_PSEUDO_HDR | sizeof(__be32)))
		return false;

	return true;
}

static bool bbdd_tx_update(struct __sk_buff *skb,
			   const struct bpf_fib_lookup *params)
{
	u8 eth_buf[sizeof(struct ethhdr)] = {};
	struct ethhdr *eth;
	struct bpf_dynptr p = {};
	u16 proto = skb->protocol;
	int ret;

	if (bpf_dynptr_from_skb(skb, 0, &p))
		return false;

	eth = bpf_dynptr_slice_rdwr(&p, 0, eth_buf, sizeof(eth_buf));
	if (!eth)
		return false;

	__builtin_memcpy(eth->h_source, params->smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, params->dmac, ETH_ALEN);
	if (eth == (void *) eth_buf) {
		ret = bpf_dynptr_write(&p, 0, eth_buf, sizeof(eth_buf), 0);
		if (ret)
			return false;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		if (!bbdd_tx_update_ipv4(skb, &p, params))
			return false;
	} else {
		if (!bbdd_tx_update_ipv6(skb, &p, params))
			return false;
	}

	return true;
}

SEC("tc")
int bbdd_tx(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_control_packet)] = {};
	struct bbdd_bfd_control_packet *bfd;
	struct bbdd_bfd_session_config *config;
	struct bbdd_bfd_session_data *data;
	struct bpf_fib_lookup params;
	u64 interval_us;
	u16 tot_len;
	u32 id;
	int ret;

	bfd = bbdd_get_bfd(skb, &tot_len, bfd_buf, sizeof bfd_buf);
	if (bfd == NULL)
		goto tx_not_bfd;

	id = bpf_ntohl(bfd->my_disc);
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
	ret = bpf_fib_lookup(skb, &params, sizeof(params),
			     config->bpf_fib_lookup_flags);
	if (ret < 0) {
		BUMP(data->diag_stats.fail_lookup);
		goto out;
	} else {
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			break;
		case BPF_FIB_LKUP_RET_BLACKHOLE:
			BUMP(data->diag_stats.dst_blackholed);
			goto out;
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			BUMP(data->diag_stats.dst_unreachable);
			goto out;
		case BPF_FIB_LKUP_RET_PROHIBIT:
			BUMP(data->diag_stats.dst_prohibited);
			goto out;
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
			BUMP(data->diag_stats.indev_no_forwarding);
			goto out;
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
			BUMP(data->diag_stats.req_encap);
			goto out;
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			bbdd_tx_notify_no_neighbor(proto, &params);
			BUMP(data->diag_stats.no_neighbor);
			goto out;
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			BUMP(data->diag_stats.req_fragmentation);
			goto out;
		case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
			BUMP(data->diag_stats.no_src_addr);
			goto out;
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			BUMP(data->diag_stats.not_forwarded);
			goto out;
		}
	}

	if (!bbdd_tx_update(skb, &params)) {
		BUMP(data->diag_stats.fail_update);
		goto out;
	}

	ret = bpf_clone_redirect(skb, params.ifindex, 0);
	if (ret) {
		BUMP(data->diag_stats.fail_redir);
		goto out;
	}

	BUMP(data->stats.tx_packets);
	__sync_fetch_and_add(&data->stats.tx_bytes, skb->len);

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
