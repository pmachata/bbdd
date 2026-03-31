/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#define BBDD_GLOBAL_DIAG_STATS(FIELD)		\
	FIELD(tx_no_session)			\
	FIELD(tx_not_bfd)			\
	FIELD(rx_packet_too_small)		\
	FIELD(rx_wrong_version_number)		\
	FIELD(rx_invalid_length)		\
	FIELD(rx_detection_multiplier_0)	\
	FIELD(rx_multipoint_not_0)		\
	FIELD(rx_discr_0)			\
	FIELD(rx_wrong_state)			\
	FIELD(rx_discr_not_found)		\
	FIELD(rx_socket_not_found)		\
	FIELD(rx_socket_assign_error)		\
	FIELD(rx_ring_buffer_error)		\
	/**/

#define BBDD_SESSION_DIAG_STATS(FIELD)		\
	FIELD(dst_blackholed)		        \
	FIELD(dst_unreachable)		        \
	FIELD(dst_prohibited)		        \
	FIELD(indev_no_forwarding)	        \
	FIELD(req_encap)		        \
	FIELD(no_neighbor)			\
	FIELD(req_fragmentation)	        \
	FIELD(no_src_addr)		        \
	FIELD(not_forwarded)		        \
	FIELD(fail_lookup)		        \
	FIELD(fail_cksum_update)	        \
	FIELD(fail_update)		        \
	FIELD(fail_redir)		        \
	FIELD(loopback_filter)		        \
	FIELD(wrong_gen_id)		        \
	/**/

#define BBDD_SESSION_STATS(FIELD)		\
	FIELD(rx_bytes)				\
	FIELD(rx_packets)		        \
	FIELD(tx_bytes)			        \
	FIELD(tx_packets)		        \
	/**/

#define STAT_FIELD(NAME) __u64 NAME;
struct bbdd_prog_global_diag_stats {
	BBDD_GLOBAL_DIAG_STATS(STAT_FIELD)
};

struct bbdd_bfd_session_config {
	struct bpf_fib_lookup fib_lookup;
	__u32 bpf_fib_lookup_flags;
	__u32 min_interval_us;
	__u32 max_interval_us;
	__u32 gen_id;
};

struct bbdd_bfd_session_data {
	struct {
		BBDD_SESSION_DIAG_STATS(STAT_FIELD)
	} diag_stats;
	struct {
		BBDD_SESSION_STATS(STAT_FIELD)
	} stats;
};

#undef STAT_FIELD

/* A copy of subset of bfddp_packet.h that does not include system headers. */

#define BFD_SINGLE_HOP_PORT	3784
#define BFD_MULTI_HOP_PORT	4784

struct bbdd_bfd_control_packet {
	uint8_t version_diag;
	uint8_t state_bits;
	uint8_t detection_multiplier;
	uint8_t length;
	__be32 local_id;
	__be32 remote_id;
	__be32 desired_tx;
	__be32 required_rx;
	__be32 required_echo_rx;
};

#define BBDD_GLOBAL_RX_SOCKETS(X)			\
	X(shop4, AF_INET, BFD_SINGLE_HOP_PORT)	\
	X(shop6, AF_INET6, BFD_SINGLE_HOP_PORT)	\
	X(mhop4, AF_INET, BFD_MULTI_HOP_PORT)	\
	X(mhop6, AF_INET6, BFD_MULTI_HOP_PORT)	\
	/**/

#define FIELD(NAME, AF, PORT) int NAME##_fd;

struct bbdd_bpf_global_config {
	__u32 veth_tx_ifindex;
	BBDD_GLOBAL_RX_SOCKETS(FIELD)
};

#undef FIELD

enum bbdd_bpf_rb_elem_type {
	BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR,
	BBDD_BPF_RB_ELEM_RX_UNK_DISCR,
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
	int ethtype;
	struct bbdd_bpf_addr addr;
};

struct bbdd_bpf_rb_elem_rx_unk_discr {
	struct bbdd_bpf_rb_elem_head head;
	int ifindex;
	int ethtype;
	__u16 dport; // xxx or sport?
	__u8 ttl;
	struct bbdd_bpf_addr saddr;
	struct bbdd_bpf_addr daddr;
	struct bbdd_bfd_control_packet packet;
};

struct bbdd_bpf_rb_elem_rx_unx_packet {
	struct bbdd_bpf_rb_elem_head head;
	struct bbdd_bfd_control_packet packet;
};

struct bbdd_bpf_rb_elem_rx_timeout {
	struct bbdd_bpf_rb_elem_head head;
	__u32 discr;
};
