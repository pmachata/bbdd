/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

typedef struct {
	BBDD_UINT16_T value;
} bbdd_be16_t;

typedef struct {
	BBDD_UINT32_T value;
} bbdd_be32_t;

typedef struct {
	BBDD_UINT64_T value;
} bbdd_be64_t;

static inline bbdd_be16_t bbdd_hton16(BBDD_UINT16_T value)
{
	return (bbdd_be16_t) {
		.value = BBDD_HTOBE16(value),
	};
}

static inline bbdd_be32_t bbdd_hton32(BBDD_UINT32_T value)
{
	return (bbdd_be32_t) {
		.value = BBDD_HTOBE32(value),
	};
}

static inline bbdd_be64_t bbdd_hton64(BBDD_UINT64_T value)
{
	return (bbdd_be64_t) {
		.value = BBDD_HTOBE64(value),
	};
}


static inline BBDD_UINT16_T bbdd_ntoh16(bbdd_be16_t value)
{
	return BBDD_BE16TOH(value.value);
}

static inline BBDD_UINT32_T bbdd_ntoh32(bbdd_be32_t value)
{
	return BBDD_BE32TOH(value.value);
}

static inline BBDD_UINT64_T bbdd_ntoh64(bbdd_be64_t value)
{
	return BBDD_BE64TOH(value.value);
}


static inline BBDD_UINT16_T bbdd_n16v(bbdd_be16_t value)
{
	return value.value;
}

static inline BBDD_UINT32_T bbdd_n32v(bbdd_be32_t value)
{
	return value.value;
}

static inline BBDD_UINT64_T bbdd_n64v(bbdd_be64_t value)
{
	return value.value;
}
