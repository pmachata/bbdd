/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once
#include <stdint.h>
#include <endian.h>

#define BBDD_UINT16_T uint16_t
#define BBDD_UINT32_T uint32_t
#define BBDD_UINT64_T uint64_t

#define BBDD_HTOBE16 htobe16
#define BBDD_HTOBE32 htobe32
#define BBDD_HTOBE64 htobe64

#define BBDD_BE16TOH htobe16
#define BBDD_BE32TOH htobe32
#define BBDD_BE64TOH htobe64

# include "bbdd-be.t"

#undef BBDD_BE64TOH
#undef BBDD_BE32TOH
#undef BBDD_BE16TOH

#undef BBDD_HTOBE64
#undef BBDD_HTOBE32
#undef BBDD_HTOBE16

#undef BBDD_UINT64_T
#undef BBDD_UINT32_T
#undef BBDD_UINT16_T
