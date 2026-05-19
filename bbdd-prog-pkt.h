/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

struct bbdd_bfd_pkt {
	uint8_t version_diag;
	uint8_t state_bits;
	uint8_t detection_multiplier;
	uint8_t length;
	bbdd_be32_t my_disc;
	bbdd_be32_t your_disc;
	bbdd_be32_t desired_tx;
	bbdd_be32_t required_rx;
	bbdd_be32_t required_echo_rx;
};

enum bbdd_bfd_pkt_state {
	BBDD_BFD_PKT_STATE_ADMINDOWN,
	BBDD_BFD_PKT_STATE_DOWN,
	BBDD_BFD_PKT_STATE_INIT,
	BBDD_BFD_PKT_STATE_UP,
};

enum bbdd_bfd_pkt_diag {
	BBDD_BFD_PKT_DIAG_NOTHING,
	BBDD_BFD_PKT_DIAG_TIME_EXPIRED,
	BBDD_BFD_PKT_DIAG_ECHO_FAILED,
	BBDD_BFD_PKT_DIAG_DOWN,
	BBDD_BFD_PKT_DIAG_FP_RESET,
	BBDD_BFD_PKT_DIAG_PATH_DOWN,
	BBDD_BFD_PKT_DIAG_CONCAT_PATH_DOWN,
	BBDD_BFD_PKT_DIAG_ADMIN_DOWN,
	BBDD_BFD_PKT_DIAG_REV_CONCAT_PATH_DOWN,
};

#define BBDD_BFD_PKT_BITS(X)			\
	X(0, MULTI,  multi)			\
	X(1, DEMAND, demand)			\
	X(2, AUTH,   auth)			\
	X(3, CPI,    cpi)			\
	X(4, FINAL,  final)			\
	X(5, POLL,   poll)			\
	/**/

#define ENUM(N, NAME, name)			\
	BBDD_BFD_PKT_BIT_ ## NAME = (1 << N),
enum bbdd_bfd_pkt_bit {
	BBDD_BFD_PKT_BITS(ENUM)
};
#undef ENUM

static inline uint8_t
bbdd_bfd_pkt_version(const struct bbdd_bfd_pkt *packet)
{
	return packet->version_diag >> 5;
}

static inline uint8_t
bbdd_bfd_pkt_diag(const struct bbdd_bfd_pkt *packet)
{
	return packet->version_diag & 0x1f;
}

static inline uint8_t
bbdd_bfd_pkt_state(const struct bbdd_bfd_pkt *packet)
{
	return packet->state_bits >> 6;
}

static inline uint8_t
bbdd_bfd_pkt_bits(const struct bbdd_bfd_pkt *packet)
{
	return packet->state_bits & 0x3f;
}
