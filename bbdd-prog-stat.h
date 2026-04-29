/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

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
	FIELD(sk_lookup_no_socket)		\
	FIELD(sk_lookup_assign_error)		\
	FIELD(monitor_error)			\
	/**/

#define BBDD_PROG_SESSION_DIAG_STATS(FIELD)	\
	FIELD(tx_dst_blackholed)		\
	FIELD(tx_dst_unreachable)		\
	FIELD(tx_dst_prohibited)		\
	FIELD(tx_indev_no_forwarding)		\
	FIELD(tx_req_encap)			\
	FIELD(tx_no_neigh)			\
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

struct bbdd_prog_session_data_stats {
	BBDD_PROG_SESSION_STATS(STAT_FIELD)
};

struct bbdd_prog_session_data_diag_stats {
	BBDD_PROG_SESSION_DIAG_STATS(STAT_FIELD)
};

#undef STAT_FIELD
