/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#define BBDD_GLOBAL_DIAG_STATS(FIELD)		\
	FIELD(tx_no_session)			\
	FIELD(tx_not_bfd)			\
	FIELD(rx_not_bfd)			\
	FIELD(rx_no_session)			\
	FIELD(rx_wrong_version_number)		\
	FIELD(rx_invalid_length)		\
	FIELD(rx_detection_multiplier_0)	\
	FIELD(rx_multipoint_not_0)		\
	FIELD(rx_my_discr_0)			\
	FIELD(rx_your_discr_0)			\
	FIELD(rx_wrong_state)			\
	FIELD(rx_discr_not_found)		\
	FIELD(rx_socket_not_found)		\
	FIELD(rx_socket_assign_error)		\
	FIELD(ring_buffer_error)		\
	/**/

#define BBDD_SESSION_DIAG_STATS(FIELD)		\
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

struct bbdd_prog_session_config {
	struct bpf_fib_lookup fib_lookup;
	__u32 bpf_fib_lookup_flags;
	__u32 min_interval_us;
	__u32 max_interval_us;
	__u32 gen_id;
	bool discr_resolved;
};

struct bbdd_prog_session_data {
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

enum bbdd_bfd_packet_state {
	BBDD_BFD_PACKET_STATE_ADMINDOWN,
	BBDD_BFD_PACKET_STATE_DOWN,
	BBDD_BFD_PACKET_STATE_INIT,
	BBDD_BFD_PACKET_STATE_UP,
};

struct bbdd_bfd_control_packet {
	uint8_t version_diag;
	uint8_t state_bits;
	uint8_t detection_multiplier;
	uint8_t length;
	__be32 my_disc;
	__be32 your_disc;
	__be32 desired_tx;
	__be32 required_rx;
	__be32 required_echo_rx;
};

static inline uint8_t
bbdd_bfd_control_packet_version(struct bbdd_bfd_control_packet *packet)
{
	return packet->version_diag >> 5;
}

static inline uint8_t
bbdd_bpf_control_packet_state(struct bbdd_bfd_control_packet *packet)
{
	return packet->state_bits >> 6;
}

struct bbdd_bpf_global_config {
	__u32 veth_rx_ifindex;
	__u32 veth_tx_ifindex;
	int ipv4_fd;
	int ipv6_fd;
};

enum bbdd_bpf_rb_elem_type {
	BBDD_BPF_RB_ELEM_TX_NO_NEIGHBOR,
	BBDD_BPF_RB_ELEM_RX_DISCR_0,
	BBDD_BPF_RB_ELEM_RX_DISCR_RESOLVE,
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
	__u8 ttl;
	__u8 multihop;
	struct bbdd_bpf_addr saddr;
	struct bbdd_bpf_addr daddr;
	struct bbdd_bfd_control_packet packet;
};

struct bbdd_bpf_rb_elem_rx_discr_resolve {
	struct bbdd_bpf_rb_elem_head head;
	__u32 local_discr;
	__u32 remote_discr;
};

struct bbdd_bpf_rb_elem_rx_unx_packet {
	struct bbdd_bpf_rb_elem_head head;
	struct bbdd_bfd_control_packet packet;
};

struct bbdd_bpf_rb_elem_rx_timeout {
	struct bbdd_bpf_rb_elem_head head;
	__u32 discr;
};
