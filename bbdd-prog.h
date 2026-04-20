/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "bbdd-prog-pkt.h"

#define BBDD_PROG_GLOBAL_DIAG_STATS(FIELD)	\
	FIELD(tx_no_session)			\
	FIELD(tx_not_bfd)			\
	FIELD(rx_not_bfd)			\
	FIELD(rx_no_session)			\
	FIELD(rx_wrong_version_number)		\
	FIELD(rx_invalid_length)		\
	FIELD(rx_your_discr_0)			\
	FIELD(rx_no_unique_session)		\
	FIELD(ring_buffer_error)		\
	/**/

#define BBDD_PROG_SESSION_DIAG_STATS(FIELD)	\
	FIELD(tx_dst_blackholed)		\
	FIELD(tx_dst_unreachable)		\
	FIELD(tx_dst_prohibited)		\
	FIELD(tx_indev_no_forwarding)		\
	FIELD(tx_req_encap)			\
	FIELD(tx_no_neighbor)			\
	FIELD(tx_req_fragmentation)		\
	FIELD(tx_no_src_addr)			\
	FIELD(tx_not_forwarded)			\
	FIELD(tx_fail_lookup)			\
	FIELD(tx_fail_cksum_update)		\
	FIELD(tx_fail_update)			\
	FIELD(tx_fail_redir)			\
	FIELD(tx_loopback_filter)		\
	FIELD(tx_wrong_gen_id)		        \
	FIELD(rx_admin_down)			\
	FIELD(rx_ttl_low)			\
	FIELD(rx_unsupported)			\
	FIELD(rx_multipoint_not_0)		\
	FIELD(rx_detection_multiplier_0)	\
	FIELD(rx_my_discr_0)			\
	FIELD(rx_your_discr_0_not_down)		\
	FIELD(rx_fail_timer)			\
	FIELD(rx_timeout)			\
	/**/

#define BBDD_PROG_SESSION_STATS(FIELD)		\
	FIELD(rx_bytes)				\
	FIELD(rx_packets)		        \
	FIELD(tx_bytes)			        \
	FIELD(tx_packets)		        \
	/**/

#define STAT_FIELD(NAME) __u64 NAME;
struct bbdd_prog_global_diag_stats {
	BBDD_PROG_GLOBAL_DIAG_STATS(STAT_FIELD)
};

struct bbdd_prog_session_config {
	struct bpf_fib_lookup fib_lookup;
	__u32 bpf_fib_lookup_flags;
	__u32 min_interval_us;
	__u32 max_interval_us;
	__u32 detect_time_us;
	__u32 gen_id;
	bool admin_down;
	__u8 ttl;
	struct bbdd_bfd_pkt rx_expect;
};

enum {
	/* When bfd.SessionState is not Up, the system MUST set
	 * bfd.DesiredMinTxInterval to a value of not less than one second
	 * (1,000,000 microseconds). */
	bbdd_prog_slow_interval_us = 1000000,
};

struct bbdd_prog_session_data_stats {
	BBDD_PROG_SESSION_STATS(STAT_FIELD)
};

struct bbdd_prog_session_data_diag_stats {
	BBDD_PROG_SESSION_DIAG_STATS(STAT_FIELD)
};

struct bbdd_prog_session_data {
	struct bpf_timer timer;
	struct bbdd_prog_session_data_stats stats;
	struct bbdd_prog_session_data_diag_stats diag_stats;
};

#undef STAT_FIELD

#define BFD_SINGLE_HOP_PORT	3784
#define BFD_MULTI_HOP_PORT	4784

struct bbdd_bpf_global_config {
	__u32 veth_rx_ifindex;
	__u32 veth_tx_ifindex;
	int ipv4_shop_fd;
	int ipv6_shop_fd;
	int ipv4_mhop_fd;
	int ipv6_mhop_fd;
};

enum bbdd_bpf_rb_elem_type {
	BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR,
	BBDD_BPF_RB_ELEM_RX_DISCR_0,
	BBDD_BPF_RB_ELEM_RX_UNX_PACKET,
	BBDD_BPF_RB_ELEM_RX_TIMEOUT,
};

struct bbdd_bpf_addr {
	__u32 addr[4];
};

struct bbdd_bpf_rb_elem_head {
	enum bbdd_bpf_rb_elem_type type;
};

struct bbdd_bpf_rb_elem_tx_no_neighbor {
	struct bbdd_bpf_rb_elem_head head;
	int ifindex;
	__u16 ethtype;
	struct bbdd_bpf_addr addr;
};

struct bbdd_bpf_rb_elem_rx_discr_0 {
	struct bbdd_bpf_rb_elem_head head;
	__u32 ifindex;
	__u16 ethtype;
	__u16 skb_len;
	__u8 ttl;
	__u8 multihop;
	struct bbdd_bpf_addr saddr;
	struct bbdd_bpf_addr daddr;
	struct bbdd_bfd_pkt packet;
};

struct bbdd_bpf_rb_elem_rx_unx_packet {
	struct bbdd_bpf_rb_elem_head head;
	__u16 skb_len;
	__u8 ttl;
	struct bbdd_bfd_pkt packet;
};

struct bbdd_bpf_rb_elem_rx_timeout {
	struct bbdd_bpf_rb_elem_head head;
	__u32 discr;
};
