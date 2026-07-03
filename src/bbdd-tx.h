/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bbdd-tx.i"

/* A slot represents deferred intent to inject a BFD packet for one
 * session. The full identity of the future call to
 * bbdd_bpf_session_inject_pkt() is captured on the slot; the caller
 * pulls slots off the queue and reissues the inject itself.
 *
 * Each session owns two slots inline — one for pending Finals and
 * one for pending Periodics. Enqueueing a slot that is already
 * linked is a no-op (natural coalescing). */
struct bbdd_tx_slot {
	uint32_t discr;
	uint32_t tx_ifindex;
	uint8_t  bfd_flags;

	bool linked;
	bool is_final;   /* Only meaningful while linked. */
	struct bbdd_tx_slot *prev, *next;
};

struct bbdd_tx *bbdd_tx_create(char **error);
void bbdd_tx_destroy(struct bbdd_tx *tx);

/* Link the slot at the tail of the finals or periodics list per
 * is_final; if it is already linked, do nothing (the older enqueue
 * subsumes the new one). On a fresh link, the slot's discr /
 * tx_ifindex / bfd_flags are stamped from the arguments. */
void bbdd_tx_enqueue(struct bbdd_tx *tx, struct bbdd_tx_slot *slot,
		     bool is_final,
		     uint32_t discr, uint32_t tx_ifindex, uint8_t bfd_flags);

/* Return the head of the finals list, or (if empty) the head of the
 * periodics list, or NULL if both are empty. Does not remove. */
struct bbdd_tx_slot *bbdd_tx_peek(const struct bbdd_tx *tx);

/* Remove the slot from whatever list it is on. Safe to call on an
 * already-unlinked slot (session-del path). */
void bbdd_tx_unlink(struct bbdd_tx *tx, struct bbdd_tx_slot *slot);

bool bbdd_tx_pending(const struct bbdd_tx *tx);
