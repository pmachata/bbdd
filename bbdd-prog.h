/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#define BBDD_GLOBAL_STATS(FIELD)		\
	FIELD(tx_no_discr)			\
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
	FIELD(packets_processed)	/*xxx*/	\
	/**/
