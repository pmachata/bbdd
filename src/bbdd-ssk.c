// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "bbdd-ssk.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include <json-c/json_tokener.h>
#include <utlist.h>

#include "bbdd-err.h"
#include "bbdd-poll.h"
#include "bbdd-sb.h"

struct bbdd_ssk_b {
	struct bbdd_ssk_peer *peers;	/* DList. */
	struct bbdd_poll_ctx *pctx;
};

struct bbdd_ssk_d {
	struct bbdd_ssk_b base;
	struct bbdd_sock sock;
	struct bbdd_ssk_cbs cb;
};

struct bbdd_ssk_c {
	struct bbdd_ssk_b base;
};

struct bbdd_ssk_peer {
	struct bbdd_ssk_b *ssb;
	struct bbdd_ssk_peer *prev;
	struct bbdd_ssk_peer *next;

	int fd;
	struct json_tokener *tok;
	struct bbdd_sb tx_sb;
	struct bbdd_ssk_cbs *cbs;	/* DList. */

	bool done;
};

int bbdd_ssk_d_fd(struct bbdd_ssk_d *ssd)
{
	return ssd->sock.fd;
}

void bbdd_ssk_peer_destroy(struct bbdd_ssk_peer *peer);

static struct bbdd_poll_ctx *bbdd_ssk_peer_pctx(struct bbdd_ssk_peer *peer)
{
	return peer->ssb->pctx;
}

static int bbdd_ssk_peer_rx(struct bbdd_ssk_peer *peer,
			    char **error)
{
	struct bbdd_ssk_cbs *cbs, *tmp;
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

		len = (size_t) rc;

		DL_FOREACH_SAFE(peer->cbs, cbs, tmp) {
			if (cbs->rx_cb != NULL) {
				rc = cbs->rx_cb(peer, buffer, len, cbs->data,
						error);
				if (rc != 0)
					return rc;
			}
		}
	}

	return 0;
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
		rc = bbdd_ssk_peer_rx(peer, &error);
		if (rc != 0) {
			bbdd_err_print(&error, "client_rx");
			goto destroy;
		}
	}

	if (revents & POLLHUP)
		goto destroy;

	if (revents & POLLOUT) {
		rc = bbdd_ssk_peer_tx(peer, &error);
		if (rc != 0) {
			bbdd_err_print(&error, "client_tx");
			goto destroy;
		}
	}

	if (bbdd_sb_len(&peer->tx_sb) > 0) {
		events |= POLLOUT;
	} else if (peer->done) {
		bbdd_ssk_peer_destroy(peer);
		return 0;
	}

	rc = bbdd_poll_set_fd(pctx, peer->fd, events,
			      bbdd_ssk_peer_event, peer, &error);
	if (rc < 0) {
		bbdd_err_print(&error, "Failed to reset SSK poll FD");
		goto destroy;
	}

	return 0;

destroy:
	bbdd_ssk_peer_destroy(peer);
	return 0;
}

struct bbdd_ssk_cbs *
bbdd_ssk_peer_add_cbs(struct bbdd_ssk_peer *peer,
		      int (*rx_cb)(struct bbdd_ssk_peer *peer, const char *buf,
				   size_t len, void *data, char **error),
		      void (*done_cb)(struct bbdd_ssk_peer *peer, void *data),
		      void *data, char **error)
{
	struct bbdd_ssk_cbs *cbs;

	cbs = malloc(sizeof(*cbs));
	if (cbs == NULL) {
		bbdd_err_fmt(error, "push peer cbs: %m");
		return NULL;
	}

	*cbs = (struct bbdd_ssk_cbs) {
		.rx_cb = rx_cb,
		.done_cb = done_cb,
		.data = data,
	};
	DL_APPEND(peer->cbs, cbs);

	return cbs;
}

void bbdd_ssk_peer_del_cbs(struct bbdd_ssk_peer *peer, struct bbdd_ssk_cbs *cbs)
{
	DL_DELETE(peer->cbs, cbs);
	free(cbs);
}

static struct bbdd_ssk_peer *
bbdd_ssk_peer_create_no_cb(struct bbdd_ssk_b *ssb, int fd, char **error)
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
		.cbs = NULL,
	};

	rc = bbdd_poll_set_fd(ssb->pctx, fd, POLLIN | POLLHUP,
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

void bbdd_ssk_peer_destroy(struct bbdd_ssk_peer *peer)
{
	struct bbdd_poll_ctx *pctx = bbdd_ssk_peer_pctx(peer);
	struct bbdd_ssk_cbs *cbs, *tmp;
	int rc;

	// xxx I suspect the flushing can't work properly on a non-blocking
	// socket.
	/* Flush what we can. */
	while (bbdd_sb_len(&peer->tx_sb) > 0) {
		rc = bbdd_ssk_peer_tx(peer, NULL);
		if (rc != 0)
			break;
	}

	DL_DELETE(peer->ssb->peers, peer);

	DL_FOREACH_SAFE(peer->cbs, cbs, tmp)
		if (cbs->done_cb != NULL)
			cbs->done_cb(peer, cbs->data);

	/* Drop the cbs in a separate loop to permit done_cb to unsubscribe on
	 * its own. */
	DL_FOREACH_SAFE(peer->cbs, cbs, tmp)
		bbdd_ssk_peer_del_cbs(peer, cbs);

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

static struct bbdd_ssk_peer *
bbdd_ssk_peer_create(struct bbdd_ssk_b *ssb, int fd,
		     struct bbdd_ssk_cbs cbs_template, char **error)
{
	struct bbdd_ssk_peer *peer;
	struct bbdd_ssk_cbs *cbs;

	peer = bbdd_ssk_peer_create_no_cb(ssb, fd, error);
	if (peer == NULL)
		return NULL;

	cbs = bbdd_ssk_peer_add_cbs(peer, cbs_template.rx_cb,
				    cbs_template.done_cb, cbs_template.data,
				    error);
	if (cbs == NULL)
		goto destroy_peer;

	return peer;

destroy_peer:
	bbdd_ssk_peer_destroy(peer);
	return NULL;
}

int bbdd_ssk_d_accept(struct bbdd_ssk_d *ssd, struct bbdd_ssk_cbs cbs,
		      struct bbdd_ssk_peer **ret_peer,
		      char **error)
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

	peer = bbdd_ssk_peer_create(&ssd->base, fd, cbs, error);
	if (peer == NULL)
		goto close_fd;

	if (ret_peer != NULL)
		*ret_peer = peer;
	return 0;

close_fd:
	close(fd);
	return -1;
}

struct bbdd_ssk_d *bbdd_ssk_open_d(struct bbdd_poll_ctx *pctx,
				   const struct bbdd_sockaddr *bsa,
				   char **error)
{
	struct bbdd_ssk_d *ssd;
	struct bbdd_sock sock;
	int rc;

	ssd = malloc(sizeof(*ssd));
	if (ssd == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	rc = bbdd_sock_open_sa(bsa, SOCK_STREAM | SOCK_CLOEXEC,
			       &sock, error);
	if (rc != 0)
		goto free_ssd;

	rc = listen(sock.fd, SOMAXCONN);
	if (rc < 0) {
		bbdd_err_fmt(error, "listen: %m");
		goto close;
	}

	*ssd = (struct bbdd_ssk_d) {
		.base = {
			.pctx = pctx,
		},
		.sock = sock,
	};
	return ssd;

close:
	bbdd_sock_close(&sock);
free_ssd:
	free(ssd);
	return NULL;
}

static void bbdd_ssk_close_b(struct bbdd_ssk_b *ssb)
{
	struct bbdd_ssk_peer *peer, *tmp;

	DL_FOREACH_SAFE(ssb->peers, peer, tmp)
		bbdd_ssk_peer_destroy(peer);
}

void bbdd_ssk_close_d(struct bbdd_ssk_d *ssd)
{
	bbdd_ssk_close_b(&ssd->base);
	bbdd_sock_close(&ssd->sock);
	free(ssd);
}

struct bbdd_ssk_c *bbdd_ssk_open_c(struct bbdd_poll_ctx *pctx,
				   const struct bbdd_sockaddr *bsa,
				   char **error)
{
	struct bbdd_ssk_peer *peer;
	struct bbdd_ssk_c *ssc;
	int fd;
	int rc;

	ssc = malloc(sizeof(*ssc));
	if (ssc == NULL) {
		bbdd_err_fmt(error, "%m");
		return NULL;
	}

	fd = ({
		struct bbdd_sock sock;
		int flags = SOCK_NONBLOCK | SOCK_STREAM | SOCK_CLOEXEC;

		rc = bbdd_sock_open_sa_nobind(bsa, flags, &sock, error);
		if (rc != 0)
			goto free_ssc;

		sock.fd;
	});

	rc = connect(fd, &bsa->sa, bsa->len);
	if (rc < 0) {
		bbdd_err_fmt(error, "Failed to connect: %m");
		goto close;
	}

	*ssc = (struct bbdd_ssk_c) {
		.base = {
			.pctx = pctx,
		},
	};

	peer = bbdd_ssk_peer_create_no_cb(&ssc->base, fd, error);
	if (peer == NULL)
		goto close;

	return ssc;

close:
	close(fd);
free_ssc:
	free(ssc);
	return NULL;
}

void bbdd_ssk_close_c(struct bbdd_ssk_c *ssc)
{
	bbdd_ssk_close_b(&ssc->base);
	free(ssc);
}

int bbdd_ssk_c_nq(struct bbdd_ssk_c *ssc, const char *buf, size_t len,
		  char **error)
{
	return bbdd_ssk_peer_nq(ssc->base.peers, buf, len, error);
}

struct bbdd_ssk_peer *bbdd_ssk_c_peer(struct bbdd_ssk_c *ssc)
{
	struct bbdd_ssk_peer *peer = ssc->base.peers;

	assert(peer != NULL);
	return peer;
}

int bbdd_ssk_peer_nq(struct bbdd_ssk_peer *peer, const char *buf, size_t len,
		     char **error)
{
	struct bbdd_poll_ctx *pctx = bbdd_ssk_peer_pctx(peer);
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
