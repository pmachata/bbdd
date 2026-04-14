/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

struct bbdd_bfd_pkt {
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
enum bbdd_bfd_pkt_bits {
	BBDD_BFD_PKT_BIT_POLL = (1 << 5),
	BBDD_BFD_PKT_BIT_FINAL = (1 << 4),
	BBDD_BFD_PKT_BIT_CPI = (1 << 3),
	BBDD_BFD_PKT_BIT_AUTH = (1 << 2),
	BBDD_BFD_PKT_BIT_DEMAND = (1 << 1),
	BBDD_BFD_PKT_BIT_MULTI = (1 << 0),
};

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
bbdd_bpf_pkt_state(const struct bbdd_bfd_pkt *packet)
{
	return packet->state_bits >> 6;
}

static inline uint8_t
bbdd_bpf_pkt_bits(const struct bbdd_bfd_pkt *packet)
{
	return packet->state_bits & 0x3f;
}
