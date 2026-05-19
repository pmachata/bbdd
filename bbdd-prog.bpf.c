// SPDX-License-Identifier: GPL-2.0+
#pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmissing-declarations"
# include "vmlinux.h"
#pragma GCC diagnostic pop

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bbdd-prog.h"

#define ETH_P_IP	0x0800          /* Internet Protocol packet */
#define ETH_P_IPV6	0x86DD          /* IPv6 over bluebook */
#define ETH_ALEN	6

#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define TC_ACT_STOLEN		5
#define TC_ACT_REDIRECT		7

#define CLOCK_MONOTONIC			1

#define	EBUSY		16	/* Device or resource busy */

enum { NS_PER_US = 1 * 1000 };
static const u32 uint32_max = -1U;

volatile int bbdd_veth_tx_ifindex;
struct bbdd_prog_global_diag_stats bbdd_prog_global_diag_stats;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bbdd_prog_session_config);
	__uint(max_entries, 16 * 1024);
} bbdd_prog_session_config_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bbdd_prog_session_data);
	__uint(max_entries, 16 * 1024);
} bbdd_prog_session_data_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} bbdd_bpf_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, bbdd_prog_sock_recv_nsocks);
	__type(key, __u32);
	__type(value, __u32);
} bbdd_bpf_sock_map SEC(".maps");

#define BUMP(COUNTER) __sync_fetch_and_add(&COUNTER, 1)

#define BBDD_ELEM_TYPE(ELEM)						\
	_Generic((ELEM),						\
		 struct bbdd_bpf_rb_elem_rx_timeout:			\
			BBDD_BPF_RB_ELEM_RX_TIMEOUT,			\
		 struct bbdd_bpf_rb_elem_rx_discr_0:			\
			BBDD_BPF_RB_ELEM_RX_DISCR_0,			\
		 struct bbdd_bpf_rb_elem_rx_unx_pkt:			\
			BBDD_BPF_RB_ELEM_RX_UNX_PKT,			\
		 struct bbdd_bpf_rb_elem_tx_no_neigh:			\
			BBDD_BPF_RB_ELEM_TX_NO_NEIGH)

#define BBDD_NOTIFY_ELEM_INIT(ELEM)					\
	do {								\
		typeof(*ELEM) *bbdd__elem;				\
		size_t sz = sizeof(*bbdd__elem);			\
									\
		bbdd__elem = bpf_ringbuf_reserve(&bbdd_bpf_rb, sz, 0);	\
		if (!bbdd__elem) {					\
			BUMP(bbdd_prog_global_diag_stats.ring_buffer_error); \
			return;						\
		}							\
									\
		bbdd__elem->head.type = BBDD_ELEM_TYPE(*bbdd__elem);	\
		(ELEM) = bbdd__elem;					\
	} while (0)

static void bbdd_tx_notify_no_neigh(u16 proto,
				    const struct bpf_fib_lookup *params)
{
	struct bbdd_bpf_rb_elem_tx_no_neigh *elem;

	BBDD_NOTIFY_ELEM_INIT(elem);

	elem->ifindex = params->ifindex;
	elem->ethtype = bpf_ntohs(proto);
	if (proto == bpf_htons(ETH_P_IP))
		elem->addr.addr[0] = params->ipv4_dst;
	else
		__builtin_memcpy(elem->addr.addr, params->ipv6_dst,
				 sizeof(elem->addr.addr));

	bpf_ringbuf_submit(elem, 0);
}

static void bbdd_rx_notify_timeout(__u32 discr)
{
	struct bbdd_bpf_rb_elem_rx_timeout *elem;

	BBDD_NOTIFY_ELEM_INIT(elem);

	elem->discr = discr;

	bpf_ringbuf_submit(elem, 0);
}

static void bbdd_rx_notify_discr_0(struct __sk_buff *skb,
				   const struct bbdd_bpf_addr *saddr,
				   const struct bbdd_bpf_addr *daddr,
				   u8 ttl, u8 multihop,
				   struct bbdd_bfd_pkt *packet)
{
	struct bbdd_bpf_rb_elem_rx_discr_0 *elem;

	BBDD_NOTIFY_ELEM_INIT(elem);

	elem->ifindex = skb->ingress_ifindex;
	elem->ethtype = bpf_ntohs(skb->protocol);
	elem->saddr = *saddr;
	elem->daddr = *daddr;
	elem->skb_len = skb->len;
	elem->ttl = ttl;
	elem->multihop = multihop;
	elem->packet = *packet;

	bpf_ringbuf_submit(elem, 0);
}

static void
bbdd_rx_notify_unx_pkt(struct __sk_buff *skb,
		       const struct bbdd_bfd_pkt *packet, u8 ttl)
{
	struct bbdd_bpf_rb_elem_rx_unx_pkt *elem;

	BBDD_NOTIFY_ELEM_INIT(elem);

	elem->packet = *packet;
	elem->skb_len = skb->len;
	elem->ttl = ttl;

	bpf_ringbuf_submit(elem, 0);
}

struct bbdd_bfd_rx_pkt_digest {
	u8 ttl;
	u8 multihop;
	struct bbdd_bpf_addr saddr;
	struct bbdd_bpf_addr daddr;
};

static bool bbdd_tx_is_bfd_ipv4(struct bpf_dynptr *p, u32 *off,
				u16 *tot_len)
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

static bool bbdd_tx_is_bfd_ipv6(struct bpf_dynptr *p, u32 *off,
				u16 *tot_len)
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

static struct bbdd_bfd_pkt *
bbdd_tx_get_bfd(struct __sk_buff *skb, u8 *bfd_buf, size_t bfd_buf_size,
		u16 *tot_len)
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
		if (!bbdd_tx_is_bfd_ipv4(&p, &off, tot_len))
			return NULL;
	} else {
		if (!bbdd_tx_is_bfd_ipv6(&p, &off, tot_len))
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
int bbdd_xmit_veth_tx(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_pkt)] = {};
	struct bbdd_bfd_pkt *bfd;
	struct bbdd_prog_session_config *config;
	struct bbdd_prog_session_data *data;
	struct bpf_fib_lookup params;
	u64 interval_us;
	u16 tot_len;
	bool final;
	u32 discr;
	int final_rc = TC_ACT_SHOT;
	int ret;

	/* SKB is an Ethernet packet. */

	bfd = bbdd_tx_get_bfd(skb, bfd_buf, sizeof bfd_buf, &tot_len);
	if (bfd == NULL)
		goto tx_not_bfd;

	final = bbdd_bfd_pkt_bits(bfd) & BBDD_BFD_PKT_BIT_FINAL;

	discr = bbdd_ntoh32(bfd->my_disc);
	config = bpf_map_lookup_elem(&bbdd_prog_session_config_hash, &discr);
	if (config == NULL)
		goto tx_no_session;

	data = bpf_map_lookup_elem(&bbdd_prog_session_data_hash, &discr);
	if (data == NULL)
		goto tx_no_session;

	if (skb->mark != config->gen_id) {
		/* Obsolete packet. */
		BUMP(data->diag_stats.tx_wrong_gen_id);
		return TC_ACT_SHOT;
	}

	/* FQ sometimes blocks packets that arrive later, but should be scheduled
	 * earlier, before packets that are already in the queue. This tends to
	 * happen e.g. during initial session handshake, where session
	 * transitions from slow start to rapid rate. Since the rapid packet is
	 * stuck behind the slow-start one, the remote session times out and the
	 * whole hand shake needs to start again.
	 *
	 * When the hash changes as gen_id gets bumped, the issue is avoided,
	 * because the two packets are considered different flows, and put to
	 * different queues.
	 *
	 * Mix up the (generally small, compared to discr) gen_id with Knuth
	 * constant to avalanche its bits around before combining with discr.
	 */
	if (!skb->hash)
		bpf_set_hash(skb, discr ^ (config->gen_id * 2654435761U));

	/* FIB lookup */
	params = config->fib_lookup;
	params.tot_len = tot_len;
	ret = bpf_fib_lookup(skb, &params, sizeof(params),
			     config->bpf_fib_lookup_flags);
	if (ret < 0) {
		BUMP(data->diag_stats.tx_fail_lookup);
		goto out;
	} else {
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			break;
		case BPF_FIB_LKUP_RET_BLACKHOLE:
			BUMP(data->diag_stats.tx_dst_blackholed);
			goto out;
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			BUMP(data->diag_stats.tx_dst_unreachable);
			goto out;
		case BPF_FIB_LKUP_RET_PROHIBIT:
			BUMP(data->diag_stats.tx_dst_prohibited);
			goto out;
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
			BUMP(data->diag_stats.tx_indev_no_forwarding);
			goto out;
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
			BUMP(data->diag_stats.tx_req_encap);
			goto out;
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			bbdd_tx_notify_no_neigh(skb->protocol, &params);
			BUMP(data->diag_stats.tx_no_neigh);
			goto out;
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			BUMP(data->diag_stats.tx_req_fragmentation);
			goto out;
		case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
			BUMP(data->diag_stats.tx_no_src_addr);
			goto out;
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			BUMP(data->diag_stats.tx_not_forwarded);
			goto out;
		}
	}

	if (params.ifindex == bbdd_veth_tx_ifindex) {
		BUMP(data->diag_stats.tx_loopback_filter);
		goto out;
	}

	if (!bbdd_tx_update(skb, &params)) {
		BUMP(data->diag_stats.tx_fail_update);
		goto out;
	}

	if (final) {
		/* bpf_redirect() return TC_ACT_REDIRECT on success, and
		 * TC_ACT_SHOT on failure. */
		final_rc = bpf_redirect(params.ifindex, 0);
		if (final_rc == TC_ACT_SHOT) {
			/* Final packets shouldn't spin around. */
			BUMP(data->diag_stats.tx_fail_redir);
			return final_rc;
		}
	} else {
		/* bpf_clone_redirect() returns 0 on success and <0 on
		 * failure. */
		ret = bpf_clone_redirect(skb, params.ifindex, 0);
		if (ret < 0) {
			BUMP(data->diag_stats.tx_fail_redir);
			goto out;
		}
	}

	BUMP(data->stats.tx_packets);
	__sync_fetch_and_add(&data->stats.tx_bytes, skb->len);

out:
	if (final)
		return final_rc;

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
int bbdd_xmit_veth_rx(struct __sk_buff *skb)
{
	return bpf_redirect(bbdd_veth_tx_ifindex, 0);
}

static int bfd_session_expired(void *hmap, u32 *key,
			       struct bbdd_prog_session_data *data)
{
	BUMP(data->diag_stats.rx_timeout);
	bbdd_rx_notify_timeout(*key);
	return 0;
}

static void bbdd_recv_rearm_timer(__u32 discr,
				  const struct bbdd_prog_session_config *config,
				  struct bbdd_prog_session_data *data)
{
	u64 detect_time_ns;
	int ret;

	if (!config->rearm_timer)
		return;

	if (!data->timer_initd) {
		ret = bpf_timer_init(&data->timer, &bbdd_prog_session_data_hash,
				     CLOCK_MONOTONIC);
		if (ret && ret != -EBUSY) {
			BUMP(data->diag_stats.ra_fail_timer);
			return;
		}

		ret = bpf_timer_set_callback(&data->timer, bfd_session_expired);
		if (ret) {
			BUMP(data->diag_stats.ra_fail_timer);
			return;
		}

		data->timer_initd = true;
	}

	detect_time_ns = config->detect_time_us * (u64)NS_PER_US;
	ret = bpf_timer_start(&data->timer, detect_time_ns, 0);
	if (ret) {
		BUMP(data->diag_stats.ra_fail_timer);
		return;
	}

	// xxx when decreasing time, we will probably need to signal to datapath
	// that the timer should be rearmed. Imagine going from 4s timeout to
	// say 1ms timeout. We would miss thousands of timeout events before the
	// timer fires and gives us an opportunity to rearm.
}

SEC("tc")
int bbdd_xmit_veth_rx_xmit(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_pkt)] = {};
	struct bbdd_prog_session_config *config;
	struct bbdd_prog_session_data *data;
	struct bbdd_bfd_pkt *bfd;
	u16 tot_len;
	u32 discr;

	/* SKB is an Ethernet packet. */

	bfd = bbdd_tx_get_bfd(skb, bfd_buf, sizeof bfd_buf, &tot_len);
	if (bfd == NULL) {
		BUMP(bbdd_prog_global_diag_stats.ra_not_bfd);
		goto shot;
	}

	discr = bbdd_ntoh32(bfd->my_disc);
	config = bpf_map_lookup_elem(&bbdd_prog_session_config_hash, &discr);
	if (config == NULL)
		goto ra_no_session;

	data = bpf_map_lookup_elem(&bbdd_prog_session_data_hash, &discr);
	if (data == NULL)
		goto ra_no_session;

	bbdd_recv_rearm_timer(discr, config, data);
	return TC_ACT_STOLEN;

ra_no_session:
	BUMP(bbdd_prog_global_diag_stats.ra_no_session);
shot:
	return TC_ACT_SHOT;
}

static bool bbdd_recv_parse_ipv4(struct __sk_buff *skb,
				 struct bbdd_bfd_rx_pkt_digest *digest)
{
	struct iphdr iph;
	long ret;

	ret = bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph),
					  BPF_HDR_START_NET);
	if (ret < 0)
		return false;

	digest->ttl = iph.ttl;
	__builtin_memcpy(&digest->saddr, &iph.saddr, sizeof(iph.saddr));
	__builtin_memcpy(&digest->daddr, &iph.daddr, sizeof(iph.daddr));

	return true;
}

static bool bbdd_recv_parse_ipv6(struct __sk_buff *skb,
				 struct bbdd_bfd_rx_pkt_digest *digest)
{
	struct ipv6hdr ip6h;
	long ret;

	ret = bpf_skb_load_bytes_relative(skb, 0, &ip6h, sizeof(ip6h),
					  BPF_HDR_START_NET);
	if (ret < 0)
		return false;

	digest->ttl = ip6h.hop_limit;
	__builtin_memcpy(&digest->saddr, &ip6h.saddr, sizeof(ip6h.saddr));
	__builtin_memcpy(&digest->daddr, &ip6h.daddr, sizeof(ip6h.daddr));

	return true;
}

static struct bbdd_bfd_pkt *
bbdd_recv_get_bfd(struct __sk_buff *skb, u8 *bfd_buf, size_t bfd_buf_size,
		  struct bbdd_bfd_rx_pkt_digest *digest)
{
	u8 udph_buf[sizeof(struct udphdr)] = {};
	struct udphdr *udph;
	struct bpf_dynptr p;
	u32 off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		if (!bbdd_recv_parse_ipv4(skb, digest))
			return NULL;
	} else {
		if (!bbdd_recv_parse_ipv6(skb, digest))
			return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &p))
		return NULL;

	off = 0;
	udph = bpf_dynptr_slice(&p, off, udph_buf, sizeof(udph_buf));
	if (!udph)
		return NULL;

	digest->multihop = udph->dest == bpf_htons(BFD_MULTI_HOP_PORT);

	off += sizeof(*udph);
	return bpf_dynptr_slice(&p, off, bfd_buf, bfd_buf_size);
}

/* This is attached to a UDP socket, so we can skip IPv4/v6/UDP validation,
 * because we know those layers are correct. It also means we need to access
 * IPv4 fields through bpf_skb_load_bytes_relative(), because the
 * bpf_dynptr_slice() interface assumes offset 0 is the UDP header.
 */
SEC("socket")
int bbdd_recv(struct __sk_buff *skb)
{
	u8 bfd_buf[sizeof(struct bbdd_bfd_pkt)] = {};
	struct bbdd_bfd_rx_pkt_digest digest = {};
	struct bbdd_prog_session_data *data;
	const struct bbdd_prog_session_config *config;
	struct bbdd_bfd_pkt *bfd;
	u32 discr;
	int ret;

	bfd = bbdd_recv_get_bfd(skb, bfd_buf, sizeof bfd_buf, &digest);
	if (bfd == NULL) {
		BUMP(bbdd_prog_global_diag_stats.rx_not_bfd);
		return TC_ACT_OK;
	}

	/* If the version number is not correct (1), the packet MUST be
	 * discarded. We need to check this here, because the payload
	 * interpretation depends on the version.
	 */
	if (bbdd_bfd_pkt_version(bfd) != 1) {
		BUMP(bbdd_prog_global_diag_stats.rx_wrong_version_number);
		return TC_ACT_SHOT;
	}

	/* If the Length field is less than the minimum correct value (24 if the
         * A bit is clear, or 26 if the A bit is set), the packet MUST be
         * discarded. If the Length field is greater than the payload of the
         * encapsulating protocol, the packet MUST be discarded.
	 *
	 * We know there was enough data to at least access the payload as
	 * represented by struct bbdd_bfd_pkt. Since that's all that we ever
	 * support, we can simply validate that the length matches.
	 */
	if (bfd->length != sizeof(*bfd)) {
		BUMP(bbdd_prog_global_diag_stats.rx_invalid_length);
		return TC_ACT_SHOT;
	}

	if (bbdd_ntoh32(bfd->your_disc) == 0) {
		/* If the Your Discriminator field is zero, the session MUST be
		 * selected based on some combination of other fields [...] */
		BUMP(bbdd_prog_global_diag_stats.rx_your_discr_0);
		bbdd_rx_notify_discr_0(skb, &digest.saddr, &digest.daddr,
				       digest.ttl, digest.multihop, bfd);
		return TC_ACT_SHOT;
	}

	discr = bbdd_ntoh32(bfd->your_disc);
	data = bpf_map_lookup_elem(&bbdd_prog_session_data_hash, &discr);
	config = bpf_map_lookup_elem(&bbdd_prog_session_config_hash, &discr);
	if (data == NULL || config == NULL) {
		BUMP(bbdd_prog_global_diag_stats.rx_no_session);
		return TC_ACT_SHOT;
	}

	/* These checks are duplicated in bbdd-bpf.c, where they are commented
	 * as well. */
	if (config->admin_down) {
		BUMP(data->diag_stats.rx_admin_down);
		return TC_ACT_SHOT;
	}
	if (config->ttl > digest.ttl) {
		BUMP(data->diag_stats.rx_ttl_low);
		return TC_ACT_SHOT;
	}

	ret = __builtin_memcmp(bfd, &config->rx_expect, sizeof(*bfd));
	if (ret != 0) {
		bbdd_rx_notify_unx_pkt(skb, bfd, digest.ttl);
		return TC_ACT_SHOT;
	}

	BUMP(data->stats.rx_packets);
	__sync_fetch_and_add(&data->stats.rx_bytes, skb->len);

	bbdd_recv_rearm_timer(discr, config, data);
	return TC_ACT_SHOT;
}

SEC("sk_lookup")
int bbdd_sk_lookup(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int ret = SK_DROP;
	__u32 idx;
	int rc;

	if (ctx->protocol != IPPROTO_UDP)
		return SK_PASS;

#define MATCH(AF, PORT, NAME)						\
		if (ctx->family == (AF) && ctx->local_port == (PORT)) {	\
			idx = BBDD_PROG_RECV_SOCK_ ## NAME ## _IX;	\
			goto matched;					\
		}

	BBDD_PROG_RECV_SOCKETS(MATCH);

	/* No match. */
	return SK_PASS;
#undef MATCH

matched:
	sk = bpf_map_lookup_elem(&bbdd_bpf_sock_map, &idx);
	if (!sk) {
		BUMP(bbdd_prog_global_diag_stats.sk_lookup_no_socket);
		return SK_PASS;
	}

	rc = bpf_sk_assign(ctx, sk, 0);
	if (rc != 0) {
		BUMP(bbdd_prog_global_diag_stats.sk_lookup_assign_error);
	} else
		ret = SK_PASS;

	bpf_sk_release(sk);
	return ret;
}

char _license[] SEC("license") = "GPL";
