/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#define BBDD_GLOBAL_STATS(FIELD)		\
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

struct bbdd_bfd_session_config {
	struct bpf_fib_lookup fib_lookup;
	__u32 bpf_fib_lookup_flags;
	__u32 min_interval_us;
	__u32 max_interval_us;
	__u32 gen_id;
};

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
