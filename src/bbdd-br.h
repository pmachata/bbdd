/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "bbdd.h"
#include "bbdd-mon.i"

struct bbdd_ec bbdd_br_start(int argc, char **argv,
			     const struct bbdd_mon_topics *topics);
