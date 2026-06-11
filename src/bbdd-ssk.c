// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "bbdd-ssk.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h> // xxx
#include <stdlib.h>
#include <unistd.h>

#include <json-c/json_tokener.h>
#include <utlist.h>

#include "bbdd-err.h"
#include "bbdd-poll.h"
#include "bbdd-sb.h"

struct bbdd_ssk_peer {
	struct bbdd_ssk_b *ssb;
	struct bbdd_ssk_peer *prev;
	struct bbdd_ssk_peer *next;

	int fd;
	struct json_tokener *tok;
	struct bbdd_sb tx_sb;
	struct bbdd_ssk_cbs cbs;

	bool done;
};

int bbdd_ssk_d_fd(struct bbdd_ssk_d *ssd)
{
	return ssd->sock.fd;
}

static void bbdd_ssk_peer_destroy(struct bbdd_ssk_peer *peer,
				  struct bbdd_poll_ctx *pctx);

static int bbdd_ssk_peer_rx(struct bbdd_ssk_peer *peer,
			    struct bbdd_poll_ctx *pctx,
			    char **error)
{
	char buffer[1024];
	size_t len;
	ssize_t rc;

	while (true) {
		rc = recv(peer->fd, buffer, sizeof(buffer), 0);
		if (rc < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			if (errno == EINTR)
				continue;

			return rc;
		}
		if (rc == 0)
			break;

		// xxx debug message
		len = (size_t) rc;

		rc = peer->cbs.rx_cb(peer, pctx, buffer, len, peer->cbs.data, error);
	}

	return rc;
}

static int bbdd_ssk_peer_tx(struct bbdd_ssk_peer *peer, char **error)
{
	const char *str = bbdd_sb_cstr(&peer->tx_sb);
	size_t len;
	ssize_t rc;

again:
	rc = send(peer->fd, str, bbdd_sb_len(&peer->tx_sb), MSG_NOSIGNAL);
	if (rc < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		bbdd_err_fmt(error, "send: %m");
		return -1;
	}

	// xxx debug message
	// fprintf(stderr, "sent %zd bytes `%*s'\n", rc, (int)rc, str);
	len = (size_t) rc;
	bbdd_sb_pull(&peer->tx_sb, len);
	return 0;
}

static int bbdd_ssk_peer_event(struct bbdd_poll_ctx *pctx, short revents,
			       void *arg, char **)
{
	struct bbdd_ssk_peer *peer = arg;
	short events = POLLIN | POLLHUP;
	char *error;
	int rc;

	if (revents & POLLIN) {
		rc = bbdd_ssk_peer_rx(peer, pctx, &error);
		if (rc != 0) {
			bbdd_err_print(&error, "client_rx");
			goto error;
		}
	}

	if (revents & POLLHUP)
		goto error;

	if (revents & POLLOUT) {
		rc = bbdd_ssk_peer_tx(peer, &error);
		if (rc != 0) {
			bbdd_err_print(&error, "client_tx");
			goto error;
		}
	}

	if (bbdd_sb_len(&peer->tx_sb) > 0) {
		events |= POLLOUT;
	} else if (peer->done) {
		bbdd_ssk_peer_destroy(peer, pctx);
		return 0;
	}

	rc = bbdd_poll_set_fd(pctx, peer->fd, events,
			      bbdd_ssk_peer_event, peer, &error);
	if (rc < 0) {
		bbdd_err_print(&error, "Failed to reset SSK poll FD");
		goto error;
	}

	return 0;

error:
	bbdd_ssk_peer_destroy(peer, pctx);
	/* Muffle errors, we don't want to break out of the poll loop. */
	return 0;
}

static struct bbdd_ssk_peer *
bbdd_ssk_peer_create(struct bbdd_ssk_b *ssb,
		     struct bbdd_poll_ctx *pctx, int fd,
		     struct bbdd_ssk_cbs cbs, char **error)
{
	struct bbdd_ssk_peer *peer;
	struct json_tokener *tok;
	int rc;

	peer = malloc(sizeof(*peer));
	if (peer == NULL) {
		bbdd_err_fmt(error, "client ctx alloc: %m");
		return NULL;
	}

	tok = json_tokener_new();
	if (tok == NULL) {
		bbdd_err_fmt(error, "json_tokener_new: %m");
		goto free_peer;
	}

	*peer = (struct bbdd_ssk_peer) {
		.ssb = ssb,
		.fd = fd,
		.tok = tok,
		.cbs = cbs,
	};

	rc = bbdd_poll_set_fd(pctx, fd, POLLIN | POLLHUP,
			      bbdd_ssk_peer_event, peer, error);
	if (rc != 0)
		goto free_tok;

	DL_APPEND(ssb->peers, peer);
	return peer;

free_tok:
	json_tokener_free(tok);
free_peer:
	free(peer);
	return NULL;
}

static void bbdd_ssk_peer_destroy(struct bbdd_ssk_peer *peer,
				  struct bbdd_poll_ctx *pctx)
{
	int rc;

	// xxx I suspect the flushing can't work properly on a non-blocking
	// socket.
	/* Flush what we can. */
	while (bbdd_sb_len(&peer->tx_sb) > 0) {
		rc = bbdd_ssk_peer_tx(peer, NULL);
		if (rc != 0)
			break;
	}

	if (peer->cbs.done_cb != NULL)
		peer->cbs.done_cb(peer, peer->cbs.data);

	DL_DELETE(peer->ssb->peers, peer);

	rc = bbdd_poll_unset_fd(pctx, peer->fd);
	if (rc != 0) {
		char *error;

		bbdd_err_fmt(&error, "client_destroy: FD not found");
		bbdd_err_print(&error, NULL);
		// xxx monitor
	}

	bbdd_sb_fini(&peer->tx_sb);
	json_tokener_free(peer->tok);
	close(peer->fd);
	free(peer);
}

int bbdd_ssk_d_accept(struct bbdd_ssk_d *ssd, struct bbdd_poll_ctx *pctx,
		      struct bbdd_ssk_cbs cbs, char **error)
{
	struct bbdd_ssk_peer *peer;
	int fd;

again:
	fd = accept4(bbdd_ssk_d_fd(ssd), NULL, NULL,
		     SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return -EWOULDBLOCK;
		if (errno == EINTR)
			goto again;
		bbdd_err_fmt(error, "accept4: %m");
		return -errno;
	}

	peer = bbdd_ssk_peer_create(&ssd->base, pctx, fd, cbs, error);
	if (peer == NULL)
		goto close_fd;

	return 0;

close_fd:
	close(fd);
	return -1;
}

int bbdd_ssk_open_d(struct bbdd_ssk_d *ssd, const struct bbdd_sockaddr *bsa,
		    char **error)
{
	struct bbdd_sock sock;
	int rc;

	rc = bbdd_sock_open_sa(bsa, SOCK_STREAM | SOCK_CLOEXEC,
			       &sock, error);
	if (rc != 0)
		return rc;

	rc = listen(sock.fd, SOMAXCONN);
	if (rc < 0) {
		bbdd_err_fmt(error, "listen: %m");
		goto close;
	}

	*ssd = (struct bbdd_ssk_d) {
		.sock = sock,
	};
	return 0;

close:
	bbdd_sock_close(&sock);
	return rc;
}

static void bbdd_ssk_close_b(struct bbdd_ssk_b *ssb, struct bbdd_poll_ctx *pctx)
{
	struct bbdd_ssk_peer *peer, *tmp;

	DL_FOREACH_SAFE(ssb->peers, peer, tmp)
		bbdd_ssk_peer_destroy(peer, pctx);
}

void bbdd_ssk_close_d(struct bbdd_ssk_d *ssd, struct bbdd_poll_ctx *pctx)
{
	bbdd_ssk_close_b(&ssd->base, pctx);
	bbdd_sock_close(&ssd->sock);
}

int bbdd_ssk_open_c(struct bbdd_ssk_c *ssc, const struct bbdd_sockaddr *bsa,
		    struct bbdd_poll_ctx *pctx,
		    struct bbdd_ssk_cbs cbs, char **error)
{
	struct bbdd_ssk_peer *peer;
	int fd;
	int rc;

	fd = ({
		struct bbdd_sock sock;
		int flags = SOCK_NONBLOCK | SOCK_STREAM | SOCK_CLOEXEC;

		rc = bbdd_sock_open_sa_nobind(bsa, flags, &sock, error);
		if (rc != 0)
			return rc;

		sock.fd;
	});

	rc = connect(fd, &bsa->sa, bsa->len);
	if (rc < 0) {
		bbdd_err_fmt(error, "Failed to connect: %m");
		goto close;
	}

	*ssc = (struct bbdd_ssk_c) {};

	peer = bbdd_ssk_peer_create(&ssc->base, pctx, fd, cbs, error);
	if (peer == NULL) {
		rc = -1;
		goto close;
	}

	return 0;

close:
	close(fd);
	return rc;
}

void bbdd_ssk_close_c(struct bbdd_ssk_c *ssc, struct bbdd_poll_ctx *pctx)
{
	bbdd_ssk_close_b(&ssc->base, pctx);
}

int bbdd_ssk_c_nq(struct bbdd_ssk_c *ssc, struct bbdd_poll_ctx *pctx,
		  const char *buf, size_t len, char **error)
{
	return bbdd_ssk_peer_nq(ssc->base.peers, pctx, buf, len, error);
}

int bbdd_ssk_peer_nq(struct bbdd_ssk_peer *peer, struct bbdd_poll_ctx *pctx,
		     const char *buf, size_t len, char **error)
{
	int rc;

	/* Do this first so that we don't have to later unpush the buffer.
	 * A useless POLLOUT is just a nop. */
	rc = bbdd_poll_set_fd(pctx, peer->fd, POLLIN | POLLOUT | POLLHUP,
			      bbdd_ssk_peer_event, peer, error);
	if (rc != 0)
		return rc;

	return bbdd_sb_push_len(&peer->tx_sb, buf, len, error);
}

int bbdd_ssk_peer_fd(struct bbdd_ssk_peer *peer)
{
	return peer->fd;
}

void bbdd_ssk_peer_mark_done(struct bbdd_ssk_peer *peer)
{
	peer->done = true;
}
