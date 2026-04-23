// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "bbdd-bfdd.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>

#include "bbdd.h"
#include "bbdd-poll.h"
#include "bbdd-prog-stat.h"
#include "bbdd-util.h"
#include "bfddp.h"

struct bbdd_bfdd {
	struct bfddp_ctx *bctx;
	int fd;
	struct bbdd_poll_ctx *pctx;

	struct bbdd_bfdd_cbs cbs;
};

static int bbdd_bfdd_handle_messages(struct bbdd_bfdd *bfdd, char **error)
{
	struct bfddp_message *msg;
	int rc;

	do {
		msg = bfddp_next_message(bfdd->bctx);
		if (msg == NULL)
			break;

		rc = bfdd->cbs.message_cb(bfdd, msg, bfdd->cbs.sock_cb_data,
					  error);
		if (rc < 0)
			return rc;
	} while (msg != NULL);

	bfddp_read_finish(bfdd->bctx);
	return 0;
}

static int bbdd_bfdd_poll_unset(struct bbdd_bfdd *bfdd)
{
	int rc;

	if (bfdd->fd >= 0) {
		rc = bbdd_poll_unset_fd(bfdd->pctx, bfdd->fd);
		if (rc < 0)
			return rc;
		bfdd->fd = -1;
	}
	return 0;
}

static int bbdd_bfdd_fmterr_errno(char **error)
{
	if (errno == 0)
		*error = NULL;
	else
		bbdd_util_fmterr(error, "%m");
	return -1;
}

static int bbdd_bfdd_read_event(struct bbdd_bfdd *bfdd, char **error)
{
	ssize_t rv;

	rv = bfddp_read(bfdd->bctx);
	if (rv == -1)
		return bbdd_bfdd_fmterr_errno(error);

	if (rv > 0 && bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: received %zd bytes\n", rv);

	return bbdd_bfdd_handle_messages(bfdd, error);
}

static int bbdd_bfdd_write_event(struct bbdd_bfdd *bfdd, char **error)
{
	ssize_t rv;

	rv = bfddp_write(bfdd->bctx);
	if (rv == -1)
		return bbdd_bfdd_fmterr_errno(error);

	if (rv > 0 && bbdd_env.verbosity > 0)
		fprintf(stderr, "bfdd: sent %zd bytes\n", rv);

	return 0;
}

static int bbdd_bfdd_event(struct bbdd_poll_ctx *pctx, short revents,
			   void *data, char **)
{
	struct bbdd_bfdd *bfdd = data;
	short events = POLLIN;
	char *error;
	int rc;

	if (revents & POLLIN) {
		rc = bbdd_bfdd_read_event(bfdd, &error);
		if (rc < 0)
			goto error;
	}

	if (revents & POLLOUT) {
		rc = bbdd_bfdd_write_event(bfdd, &error);
		if (rc < 0)
			goto error;
	}

	if (bfddp_write_pending(bfdd->bctx))
		events |= POLLOUT;

	rc = bbdd_poll_set_fd(pctx, bfdd->fd, events,
			      bbdd_bfdd_event, bfdd, &error);
	if (rc < 0) {
		bbdd_util_printerr(&error, "Failed to reset BFD poll FD");
		goto error;
	}

	return 0;

error:
	/* The sockerr callback below could call bbdd_bfdd_close(). But doesn't
	 * have to, so unset the poll FD now. */
	bbdd_bfdd_poll_unset(bfdd);

	bfdd->cbs.sockerr_cb(bfdd, error, bfdd->cbs.sock_cb_data);
	free(error);

	return 0;
}

static int bbdd_bfdd_connected(struct bbdd_poll_ctx *pctx, short,
			       void *data, char **)
{
	struct bbdd_bfdd *bfdd = data;
	char *error;
	int rv;

	rv = bfddp_is_connected(bfdd->bctx);
	if (rv == 1)
		/* bfddp_is_connected() returns `1` if still not connected. Just
		 * keep the same event handler and wait for more. */
		return 0;

	if (rv == -1) {
		bbdd_util_fmterr(&error, "Error connecting to the BFD DP socket");
		goto error;
	}

	rv = bbdd_poll_set_fd(pctx, bfdd->fd, POLLOUT,
			      bbdd_bfdd_event, bfdd, &error);
	if (rv < 0)
		goto error;

	bfdd->cbs.connected_cb(bfdd, bfdd->cbs.conn_cb_data);
	return 0;

error:
	/* The callback could call bbdd_bfdd_close(). But doesn't have to, so
	 * unset the poll FD now. */
	bbdd_bfdd_poll_unset(bfdd);
	bfdd->cbs.connect_failed_cb(bfdd, &error, bfdd->cbs.conn_cb_data);

	/* Keep any errors that we encountered here to ourselves, the daemon
	 * should stay up and running. */
	return 0;
}

struct bbdd_bfdd *bbdd_bfdd_open(const char *path,
				 struct bbdd_poll_ctx *pctx,
				 const struct bbdd_bfdd_cbs *cbs,
				 char **error)
{
	struct bbdd_sockaddr sa;
	struct bfddp_ctx *bctx;
	struct bbdd_bfdd *bfdd;
	int rc;
	int fd;

	rc = bbdd_sock_parse_addr_af(AF_UNIX, path, &sa, error);
	if (rc < 0)
		return NULL;

	bctx = bfddp_new(4096, 4096);
	if (bctx == NULL) {
		bbdd_util_fmterr(error, "Failed to open libbfd context");
		return NULL;
	}

	rc = bfddp_connect(bctx, &sa.sa, sa.len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to connect to bfd datapath socket");
		goto free_bfddp;
	}

	fd = bfddp_get_fd(bctx);
	if (fd < 0) {
		/* This shouldn't happen. */
		bbdd_util_fmterr(error, "libbfd socket closed");
		goto free_bfddp;
	}

	bfdd = malloc(sizeof(*bfdd));
	if (bfdd == NULL) {
		bbdd_util_fmterr(error, "%m");
		goto free_bfddp;
	}
	*bfdd = (struct bbdd_bfdd) {
		.bctx = bctx,
		.fd = fd,
		.pctx = pctx,
		.cbs = *cbs,
	};

	rc = bbdd_poll_set_fd(pctx, fd, POLLOUT,
			      bbdd_bfdd_connected, bfdd,
			      error);
	if (rc < 0)
		goto free_bfdd;

	return bfdd;

free_bfdd:
	free(bfdd);
free_bfddp:
	bfddp_free(bctx);
	return NULL;
}

bool bbdd_bfdd_is_connected(const struct bbdd_bfdd *bfdd)
{
	return bfddp_is_connected(bfdd->bctx) == 0;
}

void bbdd_bfdd_write_enqueue(struct bbdd_bfdd *bfdd,
			     const struct bfddp_message *msg)
{
	bfddp_write_enqueue(bfdd->bctx, msg);
}

int bbdd_bfdd_reply_counters(struct bbdd_bfdd *bfdd,
			     uint16_t msg_id, uint32_t discr,
			     const struct bbdd_prog_session_data_stats *stats,
			     char **error)
{
	struct bfddp_message msg;
	size_t written;

	msg = (struct bfddp_message) {
		.header.version = BFD_DP_VERSION,
		.header.type = htons(BFD_SESSION_COUNTERS),
		.header.id = msg_id,
		.header.length = htons(sizeof(msg.header) +
				       sizeof(msg.data.session_counters)),

		.data.session_counters = {
			.lid = htonl(discr),
			.control_input_bytes = htobe64(stats->rx_bytes),
			.control_input_packets = htobe64(stats->rx_packets),
			.control_output_bytes = htobe64(stats->tx_bytes),
			.control_output_packets = htobe64(stats->tx_packets),
			/* echo counters are zero */
		},
	};

	/* returns 0 on full buffer or the number of bytes buffered. */
	written = bfddp_write_enqueue(bfdd->bctx, &msg);
	if (written == 0) {
		bbdd_util_fmterr(error, "bfdd: Buffer full");
		return -1;
	}

	return 0;
}

void bbdd_bfdd_close(struct bbdd_bfdd *bfdd)
{
	bbdd_bfdd_poll_unset(bfdd);
	bfddp_free(bfdd->bctx);
	if (bfdd->cbs.connect_free_cb != NULL)
		bfdd->cbs.connect_free_cb(bfdd->cbs.conn_cb_data);
	if (bfdd->cbs.sock_free_cb != NULL)
		bfdd->cbs.sock_free_cb(bfdd->cbs.sock_cb_data);
	free(bfdd);
}

int bbdd_bfdd_session_to_c(const struct bfddp_session *fsess,
			   struct bbdd_c_session *csess,
			   char **error)
{
	uint32_t flags = ntohl(fsess->flags);
	int af = (flags & SESSION_IPV6) ? AF_INET6 : AF_INET;
	size_t addr_sz = (flags & SESSION_IPV6) ? 16 : 4;
	unsigned char zeroes[16] = {};

	if (flags & SESSION_ECHO) {
		bbdd_util_fmterr(error, "Echo not supported");
		return -1;
	}

	if (flags & SESSION_DEMAND) {
		bbdd_util_fmterr(error, "Demand mode not supported");
		return -1;
	}

	memset(csess, 0, sizeof(*csess));

#define SET_FLAG(name, FLAG) do {					\
		csess->flags.name.seen = true;				\
		csess->flags.name.value = !!(flags & (FLAG));		\
	} while (0)
	SET_FLAG(multihop, SESSION_MULTIHOP);
	SET_FLAG(cbit,     SESSION_CBIT);
	SET_FLAG(ipv6,     SESSION_IPV6);
	SET_FLAG(passive,  SESSION_PASSIVE);
	SET_FLAG(shutdown, SESSION_SHUTDOWN);
#undef SET_FLAG

	/* Source address is not mandatory. */
	if (memcmp(&fsess->src, zeroes, addr_sz) != 0) {
		csess->src_af = af;
		if (!inet_ntop(af, &fsess->src, csess->src,
			       sizeof(csess->src))) {
			bbdd_util_fmterr(error, "Failed to convert source address: %m");
			return -1;
		}
	}

	csess->dst_af = af;
	if (!inet_ntop(af, &fsess->dst, csess->dst, sizeof(csess->dst))) {
		bbdd_util_fmterr(error, "Failed to convert destination address: %m");
		return -1;
	}

	csess->discr = ntohl(fsess->lid);
	csess->discr_seen = (csess->discr != 0);

	csess->min_tx_us = ntohl(fsess->min_tx);
	csess->min_tx_us_seen = 1;

	csess->min_rx_us = ntohl(fsess->min_rx);
	csess->min_rx_us_seen = 1;

	csess->hold_time = ntohl(fsess->hold_time);
	csess->hold_time_seen = 1;

	csess->ttl = fsess->ttl;
	csess->ttl_seen = 1;

	csess->detect_mult = fsess->detect_mult;
	csess->detect_mult_seen = 1;

	csess->netif.ifindex = ntohl(fsess->ifindex);
	csess->netif.ifindex_seen = (csess->netif.ifindex != 0);

	if (fsess->ifname[0] != '\0') {
		/* If an interface name is too long, it will be truncated, and
		 * will subsequently fail validation. So we don't care, and this
		 * contraption silences a GCC warning. */
		(void) (snprintf(csess->netif.name,
				 sizeof(csess->netif.name),
				 "%s", fsess->ifname) != 0);
		csess->netif.name_seen = 1;
	}

	return 0;
}
