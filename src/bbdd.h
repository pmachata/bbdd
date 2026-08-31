/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* bbdd.c */

extern struct bbdd_env {
	const char *socket;
	int verbosity;
	bool show_json;
	bool numeric;
	bool timestamp;
	uint32_t stream_maxbuf; /* Maximum outstanding rx or tx buffer size.
				 * 0 means unbounded. */

	/* Debug options. */
	bool mon_eager;		/* For purposes of formatting monitoring
				 * messages, all topics should be considered
				 * enabled. This exercises message formatting
				 * paths without actually sending the
				 * messages. */
	uint32_t bfdd_delay_ms;	/* The amount of sleep in us between reception
				 * of a BFDD message and the response. */
	uint32_t tx_capacity;	/* Tx-queue capacity override: max pinned
				 * packets before enqueue kicks in. 0 means
				 * "unset", and the daemon sizes the socket
				 * dynamically from session_count. Set via
				 * --debug=tx-cap=<N> to pin a fixed value
				 * for queue-path testing. */
} bbdd_env;

struct bbdd_ec {
	int __ec;
};

extern const struct bbdd_ec bbdd_ec_success;
extern const struct bbdd_ec bbdd_ec_failure;

bool bbdd_ec_is_success(struct bbdd_ec ec);
