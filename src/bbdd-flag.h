/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

struct bbdd_flag {
	bool value;
	bool seen;
};

static inline bool bbdd_flag_isset(struct bbdd_flag flag)
{
	return flag.seen && flag.value;
}
