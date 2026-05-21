/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "bbdd-prog-be.h"
#include "bbdd-prog-pkt.h"
#include "bbdd-prog-stat.h"

struct bbdd_prog_session_config {
	struct bpf_fib_lookup fib_lookup;
	__u32 bpf_fib_lookup_flags;
	__u32 min_interval_us;
	__u32 max_interval_us;
	__u32 detect_time_us;
	__u32 gen_id;
	bool admin_down;
	bool rearm_timer;
	__u8 ttl;
	struct bbdd_bfd_pkt rx_expect;
};

enum {
	/* When bfd.SessionState is not Up, the system MUST set
	 * bfd.DesiredMinTxInterval to a value of not less than one second
	 * (1,000,000 microseconds). */
	bbdd_prog_slow_interval_us = 1000000,
};

struct bbdd_prog_session_data {
	struct bpf_timer timer;
	struct bbdd_prog_session_data_stats stats;
	struct bbdd_prog_session_data_diag_stats diag_stats;
	bool timer_initd;
};

#define BFD_SINGLE_HOP_PORT	3784
#define BFD_MULTI_HOP_PORT	4784

#define BBDD_PROG_RECV_SOCKETS(X)			\
	X(AF_INET,  BFD_SINGLE_HOP_PORT, ipv4_shop)	\
	X(AF_INET6, BFD_SINGLE_HOP_PORT, ipv6_shop)	\
	X(AF_INET,  BFD_MULTI_HOP_PORT,  ipv4_mhop)	\
	X(AF_INET6, BFD_MULTI_HOP_PORT,  ipv6_mhop)	\
	/**/

#define BBDD_PROG_SOCK_IX(AF, PORT, NAME) BBDD_PROG_RECV_SOCK_ ## NAME ## _IX,
enum {
	BBDD_PROG_RECV_SOCKETS(BBDD_PROG_SOCK_IX)
};
#undef BBDD_PROG_SOCK_IX

#define BBDD_PROG_SOCK_P1(...) +1
enum {
	bbdd_prog_sock_recv_nsocks = BBDD_PROG_RECV_SOCKETS(BBDD_PROG_SOCK_P1),
};
#undef BBDD_PROG_SOCK_P1

enum bbdd_bpf_rb_elem_type {
	BBDD_BPF_RB_ELEM_TX_NO_NEIGH,
	BBDD_BPF_RB_ELEM_RX_DISCR_0,
	BBDD_BPF_RB_ELEM_RX_UNX_PKT,
	BBDD_BPF_RB_ELEM_RX_TIMEOUT,
};

struct bbdd_bpf_addr {
	__u32 addr[4];
};

struct bbdd_bpf_rb_elem_head {
	enum bbdd_bpf_rb_elem_type type;
};

struct bbdd_bpf_rb_elem_tx_no_neigh {
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

struct bbdd_bpf_rb_elem_rx_unx_pkt {
	struct bbdd_bpf_rb_elem_head head;
	__u16 skb_len;
	__u8 ttl;
	struct bbdd_bfd_pkt packet;
};

struct bbdd_bpf_rb_elem_rx_timeout {
	struct bbdd_bpf_rb_elem_head head;
	__u32 discr;
};
