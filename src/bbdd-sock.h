/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <json-c/json_object.h>

#include "bbdd-be.h"
#include "bbdd-mon.i"
#include "bbdd-poll.i"

/* This structure is layout-compatible with the start of struct sockaddr_in and
 * struct sockaddr_in6, but not struct sockaddr_un. */
struct bddd_sockaddr_in46 {
	sa_family_t family;
	bbdd_be16_t port;
};

struct bbdd_sockaddr {
	union {
		struct sockaddr sa;
		struct bddd_sockaddr_in46 sin46;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
	};
	socklen_t len;
};

/* Per-connection state for a stream JRPC socket. Heap-allocated; lifetime
 * runs accept() to close on the server side, connect() to close on the
 * client side. */
struct bbdd_sock_peer;

struct bbdd_sock {
	int fd;
	struct bbdd_sockaddr sa;
	/* Non-NULL for stream peers (server-side accepted, or client-side
	 * connected). Carries TX buffer + RX tokener. */
	struct bbdd_sock_peer *peer;
};

int bbdd_sock_parse_u32(const char *str, uint32_t *ret, const char *what,
			char **error);
int bbdd_sock_parse_u8(const char *str, uint8_t *ret, const char *what,
		       char **error);

int bbdd_inet_pton(int af, const char *restrict addr, void *restrict dst,
		   char **error);

int bbdd_sockaddr_ntop(socklen_t bufsize;
		       const struct bbdd_sockaddr *sa,
		       char buf[bufsize], socklen_t bufsize, char **error);

const void *bbdd_sockaddr_addrbuf(const struct bbdd_sockaddr *sa,
				  size_t *size, char **error);

/* Returns 0 or 1 for false or true; or < 0 for errors. */
int bbdd_sockaddr_is_zero(const struct bbdd_sockaddr *sa, char **error);

/* Returns 0 or 1 for false or true; or < 0 for errors. */
int bbdd_sockaddr_eq(const struct bbdd_sockaddr *sa,
		     const struct bbdd_sockaddr *sb, char **error);

int bbdd_sock_split_addr_proto(char *arg, const char **proto,
			       const char **addr, const char **port,
			       char **error);
int bbdd_sock_af_from_str(const char *proto, char **error);
const char *bbdd_sock_af_to_str(int af);

/* Parse an address string in format of a given address family AF. */
int bbdd_sock_parse_addrstr(int af, const char *arg, struct bbdd_sockaddr *sa,
			    char **error);

/* Parse full <family>://<address>:<port> address. */
int bbdd_sock_parse_addr(const char *addr, struct bbdd_sockaddr *bsa,
			 int default_port, char **error);

int bbdd_sock_open_sa(const struct bbdd_sockaddr *bsa, int type,
		      struct bbdd_sock *sock, char **error);
void bbdd_sock_close(struct bbdd_sock *sock);

/* Open & listen on the daemon's JRPC control socket. The returned struct
 * holds only the listening fd; per-peer state lives on accepted-connection
 * peers. */
int bbdd_sock_open_d(struct bbdd_sock *ctl, const char *sockdir, char **error);
void bbdd_sock_close_d(struct bbdd_sock *ctl);

/* Open & connect the client side. The returned struct's `.peer' carries
 * the per-connection state (TX buffer + RX tokener). */
int bbdd_sock_open_c(struct bbdd_sock *peer,
		     const char *sockdir, char **error);
void bbdd_sock_close_c(struct bbdd_sock *peer);

/* Switch a client-side connected peer to non-blocking I/O. Required before
 * driving it from a poll loop (monitor mode). */
int bbdd_sock_set_nonblocking(struct bbdd_sock *peer, char **error);

int bbdd_sock_open_udp(struct bbdd_sockaddr addr,
		       struct bbdd_sock *sock,
		       char **error);
void bbdd_sock_close_udp(struct bbdd_sock *sock);

/* Server-side accept loop: register `dispatch' as the callback fired when a
 * complete JRPC request arrives on a peer. `ctl' must be a listening socket
 * previously returned by bbdd_sock_open_d(). */
typedef void (*bbdd_sock_dispatch_fn)(struct bbdd_sock *peer,
				      struct json_object *request,
				      void *data);

int bbdd_sock_listen_register(struct bbdd_sock *ctl,
			      struct bbdd_poll_ctx *pctx,
			      struct bbdd_mon *mon,
			      bbdd_sock_dispatch_fn dispatch,
			      void *dispatch_data,
			      char **error);

/* Tear down every accepted peer currently held by this listener. Call
 * before bbdd_sock_close_d(). */
void bbdd_sock_listen_close_peers(struct bbdd_sock *ctl);

/* Send obj on the peer. On a server-side stream peer this appends to the
 * TX buffer and arms POLLOUT if needed; on a client-side connected peer
 * this writes synchronously. */
int bbdd_sock_send(struct bbdd_sock *peer, struct json_object *obj,
		   char **error);

/* Client-side synchronous receive: block-read bytes through the peer's
 * tokener until one complete JSON object arrives. */
int bbdd_sock_recv_obj(struct bbdd_sock *peer,
		       struct json_object **obj_out, char **error);

/* For monitor-style usage on the client: process all currently-buffered or
 * available bytes, invoking `dispatch' for each complete object. Returns
 * -1 on protocol or transport error (peer is then unusable), 0 on
 * EOF/disconnect, 1 if more data may follow. */
int bbdd_sock_drain_into(struct bbdd_sock *peer,
			 void (*dispatch)(struct json_object *obj, void *data),
			 void *data, char **error);

/* Register a callback fired right before this peer is destroyed (typically
 * because the peer disconnected or the daemon is shutting down). Used by
 * modules that hold references to a peer (monitor subscribers, pending
 * async responses). Returns an opaque handle, or NULL on failure. */
void *bbdd_sock_peer_add_close_hook(struct bbdd_sock_peer *peer,
				    void (*fn)(void *data), void *data);

/* Remove a previously-registered close hook by its handle. Safe to call
 * with NULL. */
void bbdd_sock_peer_remove_close_hook(struct bbdd_sock_peer *peer,
				      void *handle);

/* Peer identity comparison for value-stored references. */
bool bbdd_sock_peer_eq(const struct bbdd_sock *a, const struct bbdd_sock *b);
