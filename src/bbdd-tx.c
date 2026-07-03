// SPDX-License-Identifier: GPL-2.0+
#include <stdlib.h>
#include <utlist.h>

#include "bbdd-err.h"
#include "bbdd-tx.h"

struct bbdd_tx {
	struct bbdd_tx_slot *finals;
	struct bbdd_tx_slot *periodics;
};

struct bbdd_tx *bbdd_tx_create(char **error)
{
	struct bbdd_tx *tx;

	tx = malloc(sizeof(*tx));
	if (tx == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}
	*tx = (struct bbdd_tx) {};
	return tx;
}

void bbdd_tx_destroy(struct bbdd_tx *tx)
{
	/* Any linked slots at destroy time are inline on session structs
	 * that are being torn down alongside; the slot memory is not
	 * ours to free. */
	free(tx);
}

bool bbdd_tx_enqueue(struct bbdd_tx *tx, struct bbdd_tx_slot *slot,
		     bool is_final,
		     uint32_t discr, uint32_t tx_ifindex, uint8_t bfd_flags)
{
	if (slot->linked)
		return false;

	slot->discr       = discr;
	slot->tx_ifindex  = tx_ifindex;
	slot->bfd_flags   = bfd_flags;
	slot->is_final   = is_final;
	slot->linked      = true;

	if (is_final)
		DL_APPEND(tx->finals, slot);
	else
		DL_APPEND(tx->periodics, slot);
	return true;
}

struct bbdd_tx_slot *bbdd_tx_peek(const struct bbdd_tx *tx)
{
	if (tx->finals != NULL)
		return tx->finals;
	return tx->periodics;
}

void bbdd_tx_unlink(struct bbdd_tx *tx, struct bbdd_tx_slot *slot)
{
	if (!slot->linked)
		return;

	if (slot->is_final)
		DL_DELETE(tx->finals, slot);
	else
		DL_DELETE(tx->periodics, slot);

	slot->linked = false;
}

bool bbdd_tx_pending(const struct bbdd_tx *tx)
{
	return tx->finals != NULL || tx->periodics != NULL;
}
