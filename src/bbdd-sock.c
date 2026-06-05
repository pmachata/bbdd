// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include "bbdd-sock.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <json-c/json_tokener.h>
#include <utlist.h>

#include "bbdd-mon.h"
#include "bbdd-poll.h"
#include "bbdd-util.h"

struct bbdd_sock_peer_close_hook {
	void (*fn)(void *data);
	void *data;
	struct bbdd_sock_peer_close_hook *prev, *next;
};

/* Per-connection state. Allocated by accept() on the server, by connect()
 * on the client. */
struct bbdd_sock_peer {
	int fd;

	/* Server-side bookkeeping (NULL on client side). */
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	bbdd_sock_dispatch_fn dispatch;
	void *dispatch_data;
	struct bbdd_sock_peer *prev, *next;	/* in listener->peers */
	bool pollout_armed;

	/* TX side. Pending bytes waiting to go to the wire. */
	char *tx_buf;
	size_t tx_cap;
	size_t tx_len;	/* bytes in tx_buf */
	size_t tx_pos;	/* bytes already written */

	/* RX side. */
	struct json_tokener *tok;
	bool rx_error;

	/* Disconnect hooks: fired in reverse-registration order before the
	 * peer is destroyed. */
	struct bbdd_sock_peer_close_hook *close_hooks;

	/* For the listening socket to find us back. */
	struct bbdd_sock *listener;
};

/* Per-listener bookkeeping kept on the listening bbdd_sock. */
struct bbdd_sock_listener_state {
	struct bbdd_poll_ctx *pctx;
	struct bbdd_mon *mon;
	bbdd_sock_dispatch_fn dispatch;
	void *dispatch_data;
	struct bbdd_sock_peer *peers;	/* DList of accepted peers */
};

/* Forward declarations. */
static struct bbdd_sock_peer *bbdd_sock_peer_alloc(int fd, char **error);
static void bbdd_sock_peer_free(struct bbdd_sock_peer *peer);
static int bbdd_sock_peer_poll_cb(struct bbdd_poll_ctx *pctx, short revents,
				  void *data, char **error);
static int bbdd_sock_set_nonblock(int fd, char **error);
static struct bbdd_sock_listener_state *
bbdd_sock_listener_state_of(struct bbdd_sock *listener); // xxx util has drifted away from being very low-level
		       // library into a catch-all of utilities. I think we need
		       // a bbdd-fmt or bbdd-err for the error-formatting stuff.
		       // Or these high-level things could be in bbdd maybe.

static int bbdd_sock_parse_range(const char *str, long long *ret,
				 long long min, long long max,
				 const char *what,
				 char **error)
{
	char *nulbyte;
	long long rv;

	errno = 0;
	rv = strtoll(str, &nulbyte, 0);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
	invalid:
		bbdd_util_fmterr(error, "Invalid %s `%s'. Expected integer [%lld,%lld] (decimal or 0x-hex)",
				 what, str, min, max);
		return -1;
	}
	/* Invalid number range. */
	if (rv < min || rv > max || errno == ERANGE)
		goto invalid;

	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		bbdd_util_fmterr(error, "Invalid %s: value `%lld' followed by garbage",
				 what, rv);
		return -1;
	}

	*ret = rv;
	return 0;
}

int bbdd_sock_parse_u8(const char *str, uint8_t *ret, const char *what,
		       char **error)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 0, UINT8_MAX, what, error);
	if (err)
		return err;

	*ret = (uint8_t) v;
	return 0;
}

int bbdd_sock_parse_u32(const char *str, uint32_t *ret, const char *what,
			char **error)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 0, UINT32_MAX, what, error);
	if (err)
		return err;

	*ret = (uint32_t) v;
	return 0;
}

static int bbdd_sock_parse_port(const char *str, uint16_t *ret_port,
				char **error)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 1, 65534, "port number", error);
	if (err)
		return err;

	*ret_port = (uint16_t) v;
	return 0;
}

static int bbdd_sock_parse_addrstr_unix(const char *sockdir,
					const char *addr,
					struct bbdd_sockaddr *bsa,
					char **error)
{
	const char *maybe_slash = "/";
	int len;

	if (sockdir[0] == '\0' || sockdir[strlen(sockdir) - 1] == '/')
		maybe_slash++;

	bsa->len = sizeof(bsa->sun);
	bsa->sun.sun_family = AF_UNIX;
	len = snprintf(bsa->sun.sun_path, sizeof(bsa->sun.sun_path),
		       "%s%s%s", sockdir, maybe_slash, addr);
	if (len < 0) {
		bbdd_util_fmterr(error, "Failed to parse UNIX domain socket address: %m");
		return len;
	}
	if ((unsigned) len >= sizeof(bsa->sun.sun_path)) {
		bbdd_util_fmterr(error, "UNIX domain socket address too long");
		return -ENOBUFS;
	}

	return 0;
}

int bbdd_inet_pton(int af, const char *restrict addr, void *restrict dst,
		   char **error)
{
	int rc;

	rc = inet_pton(af, addr, dst);
	if (rc == 1)
		return 0;

	if (rc == -1) {
		bbdd_util_fmterr(error, "Invalid address family `%d'", af);
		return -1;
	}

	bbdd_util_fmterr(error, "Invalid address: `%s'", addr);
	return -1;
}

static int bbdd_sock_unsupported_family(int af, char **error)
{
	bbdd_util_fmterr(error, "Unsupported address family %d", af);
	return -1;
}

const void *bbdd_sockaddr_addrbuf(const struct bbdd_sockaddr *sa,
				  size_t *size, char **error)
{
	int af = sa->sa.sa_family;

	switch (af) {
	case AF_INET:
		if (size != NULL)
			*size = sizeof(sa->sin.sin_addr);
		return &sa->sin.sin_addr;
	case AF_INET6:
		if (size != NULL)
			*size = sizeof(sa->sin6.sin6_addr);
		return &sa->sin6.sin6_addr;
	case AF_UNIX:
	default:
		bbdd_sock_unsupported_family(af, error);
		return NULL;
	}
}

int bbdd_sockaddr_is_zero(const struct bbdd_sockaddr *sa, char **error)
{
	size_t size;
	const unsigned char *buf;

	buf = bbdd_sockaddr_addrbuf(sa, &size, error);
	if (buf == NULL)
		return -1;

	for (size_t i = 0; i < size; i++)
		if (buf[i] != 0)
			return 0;
	return 1;
}

int bbdd_sockaddr_eq(const struct bbdd_sockaddr *sa,
		     const struct bbdd_sockaddr *sb, char **error)
{
	size_t sza, szb;
	const unsigned char *ba, *bb;

	if (sa->sa.sa_family != sb->sa.sa_family)
		return 0;

	ba = bbdd_sockaddr_addrbuf(sa, &sza, error);
	if (ba == NULL)
		return -1;

	bb = bbdd_sockaddr_addrbuf(sb, &szb, error);
	if (bb == NULL)
		return -1;

	assert(sza == szb);
	return memcmp(ba, bb, sza) == 0;
}

int bbdd_sockaddr_ntop(socklen_t bufsize;
		       const struct bbdd_sockaddr *sa,
		       char buf[bufsize], socklen_t bufsize, char **error)
{
	int af = sa->sa.sa_family;
	const char *ret = NULL;
	const void *addrbuf;

	addrbuf = bbdd_sockaddr_addrbuf(sa, NULL, error);
	if (addrbuf == NULL)
		return -1;

	ret = inet_ntop(af, addrbuf, buf, bufsize);
	if (ret == NULL) {
		bbdd_util_fmterr(error, "Failed to format address: %m");
		return -1;
	}

	return 0;
}

static int bbdd_sock_split_addr_unix(char *addr,
				     const char **ret_addr,
				     const char **ret_port)
{
	*ret_addr = addr;
	*ret_port = NULL;
	return 0;
}

static int bbdd_sock_split_addr_ipv4(char *addr, bool allow_port,
				     const char **ret_addr,
				     const char **ret_port,
				     char **error)
{
	char *port;

	port = allow_port ? strchr(addr, ':') : NULL;
	if (port != NULL) {
		if (!allow_port) {
			bbdd_util_fmterr(error, "Port disallowed");
			return -EINVAL;
		}
		*port++ = '\0';
	}

	*ret_addr = addr;
	if (ret_port != NULL)
		*ret_port = port;
	return 0;
}

static int bbdd_sock_split_addr_ipv6_port(char *addr,
					  const char **ret_addr,
					  const char **ret_port,
					  char **error)
{
	const char *port = NULL;
	char *saux;

	/* Check & skip '['. */
	if (*addr++ != '[') {
	no_brackets:
		bbdd_util_fmterr(error, "IPv6 address needs to be []-enclosed");
		return -1;
	}

	/* Check ']' and ... */
	saux = strrchr(addr, ']');
	if (saux == NULL)
		goto no_brackets;
	*saux++ = '\0'; /* ... terminate the address string. */

	/* Check & skip ':', parse port if any. */
	if (*saux == ':') {
		saux++;
		port = saux;
	} else if (*saux != '\0') {
		bbdd_util_fmterr(error, "Invalid address `%s': Garbage after closing bracket",
				 addr);
		return -EINVAL;
	}

	*ret_addr = addr;
	*ret_port = port;
	return 0;
}

/* strdupa(), but bound the size reasonably. */
#define bbdd_sock_strdupa(STR, ERROR)					\
	({								\
		/* something://[<INET6_ADDRSTRLEN>]:<5-digit-PORT> */	\
		size_t len = INET6_ADDRSTRLEN + sizeof "something://[]:" + 5; \
		const char *str = (STR);				\
		char *ret = NULL;					\
		if (strlen(str) > len)					\
			bbdd_util_fmterr((ERROR), "IPv address too long"); \
		else							\
			ret = strdupa(str);				\
		ret;							\
	})

static int bbdd_sock_parse_addrstr_ipv4(const char *str_in,
					struct bbdd_sockaddr *bsa,
					char **error)
{
	const char *addr;
	char *copy;
	int rc;

	copy = bbdd_sock_strdupa(str_in, error);
	if (copy == NULL)
		return -1;

	rc = bbdd_sock_split_addr_ipv4(copy, false, &addr, NULL, error);
	if (rc < 0)
		return rc;

	bsa->len = sizeof(bsa->sin);
	bsa->sin.sin_family = AF_INET;
	bsa->sin.sin_port = 0;
	return bbdd_inet_pton(AF_INET, addr, &bsa->sin.sin_addr, error);
}

static int bbdd_sock_parse_addrstr_ipv6(const char *addr,
					struct bbdd_sockaddr *bsa,
					char **error)
{
	bsa->len = sizeof(bsa->sin6);
	bsa->sin6.sin6_family = AF_INET6;
	bsa->sin6.sin6_port = 0;
	return bbdd_inet_pton(AF_INET6, addr, &bsa->sin6.sin6_addr, error);
}

struct bbdd_sock_proto {
	int af;
	const char *name;
};
static struct bbdd_sock_proto bbdd_sock_protos[] = {
	{ AF_UNIX, "unix" },
	{ AF_INET, "ipv4" },
	{ AF_INET6, "ipv6" },
};

int bbdd_sock_af_from_str(const char *proto, char **error)
{
	for (size_t i = 0; i < ARRAY_SIZE(bbdd_sock_protos); i++)
		if (strcmp(proto, bbdd_sock_protos[i].name) == 0)
			return bbdd_sock_protos[i].af;

	bbdd_util_fmterr(error, "invalid socket protocol `%s'", proto);
	return -1;
}

const char *bbdd_sock_af_to_str(int af)
{
	for (size_t i = 0; i < ARRAY_SIZE(bbdd_sock_protos); i++)
		if (bbdd_sock_protos[i].af == af)
			return bbdd_sock_protos[i].name;
	return NULL;
}

static int __bbdd_sock_split_addr_proto(char *arg, int *ret_af,
					const char **ret_proto,
					const char **ret_addr,
					const char **ret_port,
					char **error)
{
	char *colon;
	char *rest;
	int af;

	colon = strchr(arg, ':');
	if (colon == NULL) {
		bbdd_util_fmterr(error, "Invalid address format: %s", arg);
		return -1;
	}

	rest = colon + 1;
	*colon = '\0';
	*ret_proto = arg;

	af = bbdd_sock_af_from_str(arg, error);
	if (af < 0)
		return af;
	*ret_af = af;

	switch (af) {
	case AF_UNIX:
		return bbdd_sock_split_addr_unix(rest, ret_addr, ret_port);
	case AF_INET:
		return bbdd_sock_split_addr_ipv4(rest, true, ret_addr, ret_port,
						 error);
	case AF_INET6:
		return bbdd_sock_split_addr_ipv6_port(rest, ret_addr, ret_port,
						      error);
	}

	return bbdd_sock_unsupported_family(af, error);
}

int bbdd_sock_split_addr_proto(char *arg, const char **ret_proto,
			       const char **ret_addr, const char **ret_port,
			       char **error)
{
	int af;

	return __bbdd_sock_split_addr_proto(arg, &af, ret_proto, ret_addr,
					    ret_port, error);
}

int bbdd_sock_parse_addrstr(int af, const char *addr, struct bbdd_sockaddr *bsa,
			    char **error)
{
	switch (af) {
	case AF_UNIX:
		return bbdd_sock_parse_addrstr_unix("", addr, bsa, error);
	case AF_INET:
		return bbdd_sock_parse_addrstr_ipv4(addr, bsa, error);
	case AF_INET6:
		return bbdd_sock_parse_addrstr_ipv6(addr, bsa, error);
	default:
		return bbdd_sock_unsupported_family(af, error);
	}
}

int bbdd_sock_parse_addr(const char *addr, struct bbdd_sockaddr *bsa,
			 int default_port, char **error)
{
	const char *addrstr;
	const char *proto;
	const char *port;
	uint16_t port_num;
	char *copy;
	int af;
	int rc;

	copy = bbdd_sock_strdupa(addr, error);
	if (copy == NULL)
		return -1;

	rc = __bbdd_sock_split_addr_proto(copy, &af, &proto, &addrstr, &port,
					  error);
	if (rc != 0)
		return rc;

	rc = bbdd_sock_parse_addrstr(af, addrstr, bsa, error);
	if (rc != 0)
		return rc;

	switch (af) {
	case AF_UNIX:
		return 0;
	case AF_INET:
	case AF_INET6:
		port_num = default_port;
		if (port != NULL) {
			rc = bbdd_sock_parse_port(port, &port_num, error);
			if (rc != 0)
				return rc;
		}
		bsa->sin46.port = bbdd_hton16(port_num);
		return 0;
	}

	return bbdd_sock_unsupported_family(af, error);
}

static int bbdd_ctl_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *ctl_bsa, char **error)
{
	return bbdd_sock_parse_addrstr_unix(sockdir, "bbdd.ctl", ctl_bsa,
					    error);
}


static int bbdd_sock_open_sa_nobind(const struct bbdd_sockaddr *bsa,
				    int type, struct bbdd_sock *sock,
				    char **error)
{
	int fd;

	*sock = (struct bbdd_sock) { .fd = -1 };

	fd = socket(bsa->sa.sa_family, type, 0);
	if (fd < 0) {
		bbdd_util_fmterr(error, "Failed to open socket: %m");
		return -1;
	}

	*sock = (struct bbdd_sock) {
		.fd = fd,
		.sa = *bsa,
	};
	return 0;
}

void bbdd_sock_close(struct bbdd_sock *sock)
{
	close(sock->fd);

	switch (sock->sa.sa.sa_family) {
	case AF_UNIX:
		unlink(sock->sa.sun.sun_path);
		break;
	case AF_INET:
	case AF_INET6:
		break;
	}
}

static int bbdd_sock_reuseaddr(struct bbdd_sock *sock, char **error)
{
	int af = sock->sa.sa.sa_family;

	switch (af) {
	case AF_UNIX:
		unlink(sock->sa.sun.sun_path);
		return 0;

	default:
		return bbdd_sock_unsupported_family(af, error);
	}
}

int bbdd_sock_open_sa(const struct bbdd_sockaddr *bsa, int type,
		      struct bbdd_sock *sock, char **error)
{
	int rc;

	if (bsa->sa.sa_family != AF_UNIX)
		/* For now bounce everything non-unix. */
		return bbdd_sock_unsupported_family(bsa->sa.sa_family, error);

	rc = bbdd_sock_open_sa_nobind(bsa, type, sock, error);
	if (rc != 0)
		return rc;

	rc = bbdd_sock_reuseaddr(sock, error);
	if (rc != 0)
		goto close_sock;

	rc = bind(sock->fd, &bsa->sa, bsa->len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to bind socket: %m");
		goto close_sock;
	}

	return 0;

close_sock:
	bbdd_sock_close(sock);
	return rc;
}

int bbdd_sock_open_d(struct bbdd_sock *ctl, const char *sockdir, char **error)
{
	struct bbdd_sockaddr bsa;
	int rc;

	rc = bbdd_ctl_sockaddr(sockdir, &bsa, error);
	if (rc != 0)
		goto err;

	rc = bbdd_sock_open_sa(&bsa, SOCK_STREAM, ctl, error);
	if (rc != 0)
		goto err;

	rc = bbdd_sock_set_nonblock(ctl->fd, error);
	if (rc != 0)
		goto close_sock;

	rc = listen(ctl->fd, SOMAXCONN);
	if (rc < 0) {
		bbdd_util_fmterr(error, "listen: %m");
		goto close_sock;
	}

	return 0;

close_sock:
	bbdd_sock_close(ctl);
err:
	bbdd_util_appenderr(error, "Failed to open daemon socket");
	return rc;
}

void bbdd_sock_close_d(struct bbdd_sock *ctl)
{
	bbdd_sock_listen_close_peers(ctl);
	free(bbdd_sock_listener_state_of(ctl));
	ctl->peer = NULL;
	bbdd_sock_close(ctl);
}

int bbdd_sock_open_c(struct bbdd_sock *peer,
		     const char *sockdir,
		     char **error)
{
	struct bbdd_sockaddr ctl_bsa;
	int rc;

	rc = bbdd_ctl_sockaddr(sockdir, &ctl_bsa, error);
	if (rc != 0)
		return rc;

	rc = bbdd_sock_open_sa_nobind(&ctl_bsa, SOCK_STREAM, peer, error);
	if (rc != 0)
		return rc;

	rc = connect(peer->fd, &ctl_bsa.sa, ctl_bsa.len);
	if (rc != 0) {
		bbdd_util_fmterr(error, "Failed to connect to socket `%s': %m",
				 ctl_bsa.sun.sun_path);
		goto close;
	}

	peer->peer = bbdd_sock_peer_alloc(peer->fd, error);
	if (peer->peer == NULL)
		goto close;

	return 0;

close:
	close(peer->fd);
	peer->fd = -1;
	return -1;
}

void bbdd_sock_close_c(struct bbdd_sock *cli)
{
	if (cli->peer != NULL)
		bbdd_sock_peer_free(cli->peer);
	cli->peer = NULL;
	if (cli->fd >= 0)
		close(cli->fd);
	cli->fd = -1;
}

int bbdd_sock_set_nonblocking(struct bbdd_sock *peer, char **error)
{
	return bbdd_sock_set_nonblock(peer->fd, error);
}

int bbdd_sock_open_udp(struct bbdd_sockaddr addr,
		       struct bbdd_sock *sock,
		       char **error)
{
	int one = 1;
	int fd;
	int rc;

	switch (addr.sa.sa_family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		bbdd_util_fmterr(error, "bbdd_sock_open_udp: family `%d' not supported",
				 addr.sa.sa_family);
		return -1;
	}

	fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		bbdd_util_fmterr(error, "socket(af=%d, SOCK_DGRAM): %s",
				 addr.sa.sa_family, strerror(errno));
		return -1;
	}

	if (addr.sa.sa_family == AF_INET6) {
		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				&one, sizeof(one));
		if (rc < 0) {
			bbdd_util_fmterr(error, "IPV6_V6ONLY: %s",
					 strerror(errno));
			goto close_fd;
		}
	}

	rc = bind(fd, &addr.sa, addr.len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "bind: %m");
		goto close_fd;
	}

	*sock = (struct bbdd_sock) {
		.fd = fd,
		.sa = addr,
	};

	return 0;

close_fd:
	close(fd);
	return -1;
}

void bbdd_sock_close_udp(struct bbdd_sock *sock)
{
	close(sock->fd);
}

/* ===== stream peer machinery ===== */

static int bbdd_sock_set_nonblock(int fd, char **error)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		bbdd_util_fmterr(error, "fcntl(F_GETFL): %m");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		bbdd_util_fmterr(error, "fcntl(F_SETFL O_NONBLOCK): %m");
		return -1;
	}
	return 0;
}

static struct bbdd_sock_peer *bbdd_sock_peer_alloc(int fd, char **error)
{
	struct bbdd_sock_peer *peer;

	peer = malloc(sizeof(*peer));
	if (peer == NULL) {
		bbdd_util_fmterr(error, "%m");
		return NULL;
	}

	*peer = (struct bbdd_sock_peer) {
		.fd = fd,
	};

	peer->tok = json_tokener_new();
	if (peer->tok == NULL) {
		bbdd_util_fmterr(error, "json_tokener_new: %m");
		free(peer);
		return NULL;
	}

	return peer;
}

static void bbdd_sock_peer_free(struct bbdd_sock_peer *peer)
{
	struct bbdd_sock_peer_close_hook *hook, *tmp;

	if (peer == NULL)
		return;

	/* Run close hooks in reverse-registration order. */
	while (peer->close_hooks != NULL) {
		hook = peer->close_hooks->prev;
		DL_DELETE(peer->close_hooks, hook);
		hook->fn(hook->data);
		free(hook);
	}

	if (peer->tok != NULL)
		json_tokener_free(peer->tok);
	free(peer->tx_buf);
	free(peer);

	(void) tmp;
}

void *bbdd_sock_peer_add_close_hook(struct bbdd_sock_peer *peer,
				    void (*fn)(void *data), void *data)
{
	struct bbdd_sock_peer_close_hook *hook;

	hook = malloc(sizeof(*hook));
	if (hook == NULL)
		return NULL;
	*hook = (struct bbdd_sock_peer_close_hook) {
		.fn = fn,
		.data = data,
	};
	DL_APPEND(peer->close_hooks, hook);
	return hook;
}

void bbdd_sock_peer_remove_close_hook(struct bbdd_sock_peer *peer,
				      void *handle)
{
	struct bbdd_sock_peer_close_hook *hook = handle;

	if (hook == NULL)
		return;
	DL_DELETE(peer->close_hooks, hook);
	free(hook);
}

bool bbdd_sock_peer_eq(const struct bbdd_sock *a, const struct bbdd_sock *b)
{
	return a->peer != NULL && a->peer == b->peer;
}

static int bbdd_sock_peer_arm_pollout(struct bbdd_sock_peer *peer,
				      char **error)
{
	int rc;

	if (peer->pollout_armed)
		return 0;
	rc = bbdd_poll_set_fd(peer->pctx, peer->fd, POLLIN | POLLOUT,
			      bbdd_sock_peer_poll_cb, peer, error);
	if (rc != 0)
		return rc;
	peer->pollout_armed = true;
	return 0;
}

static int bbdd_sock_peer_disarm_pollout(struct bbdd_sock_peer *peer,
					 char **error)
{
	int rc;

	if (!peer->pollout_armed)
		return 0;
	rc = bbdd_poll_set_fd(peer->pctx, peer->fd, POLLIN,
			      bbdd_sock_peer_poll_cb, peer, error);
	if (rc != 0)
		return rc;
	peer->pollout_armed = false;
	return 0;
}

/* Best-effort drain of the peer's TX buffer. With pctx set (server-side
 * non-blocking peer), short writes leave bytes in the buffer and POLLOUT
 * is armed. Without pctx (client-side blocking peer), this loops until
 * fully drained or a hard error occurs. */
static int bbdd_sock_peer_drain_tx(struct bbdd_sock_peer *peer, char **error)
{
	while (peer->tx_pos < peer->tx_len) {
		ssize_t n;

		n = send(peer->fd, peer->tx_buf + peer->tx_pos,
			 peer->tx_len - peer->tx_pos, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			bbdd_util_fmterr(error, "write: %m");
			return -1;
		}
		peer->tx_pos += (size_t)n;
	}

	if (peer->tx_pos >= peer->tx_len) {
		peer->tx_len = 0;
		peer->tx_pos = 0;
		if (peer->pctx != NULL)
			return bbdd_sock_peer_disarm_pollout(peer, error);
		return 0;
	}

	/* Partial drain. Arm POLLOUT to be notified when more can be
	 * written. */
	if (peer->pctx != NULL)
		return bbdd_sock_peer_arm_pollout(peer, error);
	return 0;
}

static int bbdd_sock_peer_enqueue(struct bbdd_sock_peer *peer,
				  const char *buf, size_t len, char **error)
{
	size_t need;

	/* Compact head if we can without growing. */
	if (peer->tx_pos > 0) {
		memmove(peer->tx_buf,
			peer->tx_buf + peer->tx_pos,
			peer->tx_len - peer->tx_pos);
		peer->tx_len -= peer->tx_pos;
		peer->tx_pos = 0;
	}

	need = peer->tx_len + len;
	if (need > peer->tx_cap) {
		size_t new_cap = peer->tx_cap ? peer->tx_cap : 4096;
		char *new_buf;

		while (new_cap < need)
			new_cap *= 2;
		new_buf = realloc(peer->tx_buf, new_cap);
		if (new_buf == NULL) {
			bbdd_util_fmterr(error, "%m");
			return -1;
		}
		peer->tx_buf = new_buf;
		peer->tx_cap = new_cap;
	}

	memcpy(peer->tx_buf + peer->tx_len, buf, len);
	peer->tx_len += len;
	return 0;
}

int bbdd_sock_send(struct bbdd_sock *sock, struct json_object *obj,
		   char **error)
{
	struct bbdd_sock_peer *peer = sock->peer;
	const char *str;
	size_t len;
	int rc;

	if (peer == NULL) {
		bbdd_util_fmterr(error, "bbdd_sock_send on a non-stream socket");
		return -1;
	}

	str = json_object_to_json_string(obj);
	if (str == NULL) {
		bbdd_util_fmterr(error, "Failed to serialize JSON object");
		return -1;
	}
	len = strlen(str);

	rc = bbdd_sock_peer_enqueue(peer, str, len, error);
	if (rc != 0)
		return rc;
	return bbdd_sock_peer_drain_tx(peer, error);
}

/* Feed `len' bytes from `buf' to the tokener. If a complete object lands,
 * call `dispatch'. Returns 0 on clean progress, -1 on protocol error. */
static int bbdd_sock_peer_feed(struct bbdd_sock_peer *peer,
			       const char *buf, size_t len,
			       void (*dispatch)(struct json_object *obj,
						void *data),
			       void *data, char **error)
{
	const char *cursor = buf;
	size_t left = len;

	while (left > 0) {
		struct json_object *obj;
		size_t consumed;
		int err;

		obj = json_tokener_parse_ex(peer->tok, cursor, (int) left);
		err = json_tokener_get_error(peer->tok);

		if (obj == NULL && err == json_tokener_continue) {
			/* Need more bytes; the tokener has buffered what we
			 * fed it. */
			break;
		}

		if (obj == NULL) {
			bbdd_util_fmterr(error, "JSON parse error: %s",
					 json_tokener_error_desc(err));
			peer->rx_error = true;
			return -1;
		}

		consumed = (size_t) json_tokener_get_parse_end(peer->tok);
		assert(consumed <= left);
		cursor += consumed;
		left -= consumed;

		dispatch(obj, data);
		json_object_put(obj);

		json_tokener_reset(peer->tok);
	}

	return 0;
}

struct bbdd_sock_dispatch_ctx {
	struct bbdd_sock *peer_sock;
	bbdd_sock_dispatch_fn fn;
	void *data;
};

static void bbdd_sock_dispatch_trampoline(struct json_object *obj, void *data)
{
	struct bbdd_sock_dispatch_ctx *ctx = data;

	ctx->fn(ctx->peer_sock, obj, ctx->data);
}

static int bbdd_sock_peer_read_some(struct bbdd_sock_peer *peer,
				    void (*dispatch)(struct json_object *,
						     void *),
				    void *data, bool *got_eof, char **error)
{
	char buf[4096];
	ssize_t n;
	int rc;

	*got_eof = false;

	for (;;) {
		n = read(peer->fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			bbdd_util_fmterr(error, "read: %m");
			return -1;
		}
		if (n == 0) {
			*got_eof = true;
			return 0;
		}

		rc = bbdd_sock_peer_feed(peer, buf, (size_t) n,
					 dispatch, data, error);
		if (rc != 0)
			return rc;
	}
}

static struct bbdd_sock_listener_state *
bbdd_sock_listener_state_of(struct bbdd_sock *listener)
{
	/* The listener bbdd_sock stores its state via the `peer' pointer
	 * slot (which is otherwise unused on a listening socket). */
	return (struct bbdd_sock_listener_state *) listener->peer;
}

static int bbdd_sock_peer_poll_cb(struct bbdd_poll_ctx *pctx, short revents,
				  void *data, char **out_error)
{
	struct bbdd_sock_peer *peer = data;
	struct bbdd_sock *listener = peer->listener;
	struct bbdd_sock_listener_state *st = NULL;
	struct bbdd_sock peer_sock = {
		.fd = peer->fd,
		.peer = peer,
	};
	struct bbdd_sock_dispatch_ctx dctx;
	char *error = NULL;
	bool got_eof = false;
	int rc;

	(void) pctx;
	(void) out_error;

	if (listener != NULL)
		st = bbdd_sock_listener_state_of(listener);

	if (revents & POLLOUT) {
		rc = bbdd_sock_peer_drain_tx(peer, &error);
		if (rc != 0)
			goto teardown;
	}

	if (revents & POLLIN) {
		dctx = (struct bbdd_sock_dispatch_ctx) {
			.peer_sock = &peer_sock,
			.fn = peer->dispatch,
			.data = peer->dispatch_data,
		};
		rc = bbdd_sock_peer_read_some(peer,
					      bbdd_sock_dispatch_trampoline,
					      &dctx, &got_eof, &error);
		if (rc != 0)
			goto teardown;
		if (got_eof)
			goto teardown;
	}

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		goto teardown;

	return 0;

teardown:
	if (error != NULL) {
		bbdd_mon_senderr(peer->mon, &error, "peer fd %d", peer->fd);
		/* bbdd_mon_senderr consumes and frees *error. */
	}
	if (st != NULL)
		DL_DELETE(st->peers, peer);
	bbdd_poll_unset_fd(peer->pctx, peer->fd);
	close(peer->fd);
	bbdd_sock_peer_free(peer);
	return 0;
}

static int bbdd_sock_listen_accept_cb(struct bbdd_poll_ctx *pctx, short revents,
				      void *data, char **error)
{
	struct bbdd_sock *listener = data;
	struct bbdd_sock_listener_state *st = bbdd_sock_listener_state_of(listener);

	(void) pctx;
	(void) revents;

	for (;;) {
		struct bbdd_sock_peer *peer;
		int fd;

		fd = accept4(listener->fd, NULL, NULL,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			if (errno == EINTR)
				continue;
			bbdd_util_fmterr(error, "accept: %m");
			return -1;
		}

		peer = bbdd_sock_peer_alloc(fd, error);
		if (peer == NULL) {
			close(fd);
			return -1;
		}

		peer->pctx = st->pctx;
		peer->mon = st->mon;
		peer->dispatch = st->dispatch;
		peer->dispatch_data = st->dispatch_data;
		peer->listener = listener;

		if (bbdd_poll_set_fd(peer->pctx, peer->fd, POLLIN,
				     bbdd_sock_peer_poll_cb, peer,
				     error) != 0) {
			close(fd);
			bbdd_sock_peer_free(peer);
			return -1;
		}

		DL_APPEND(st->peers, peer);
	}
}

int bbdd_sock_listen_register(struct bbdd_sock *ctl,
			      struct bbdd_poll_ctx *pctx,
			      struct bbdd_mon *mon,
			      bbdd_sock_dispatch_fn dispatch,
			      void *dispatch_data,
			      char **error)
{
	struct bbdd_sock_listener_state *st;
	int rc;

	st = malloc(sizeof(*st));
	if (st == NULL) {
		bbdd_util_fmterr(error, "%m");
		return -1;
	}
	*st = (struct bbdd_sock_listener_state) {
		.pctx = pctx,
		.mon = mon,
		.dispatch = dispatch,
		.dispatch_data = dispatch_data,
	};
	ctl->peer = (struct bbdd_sock_peer *) st;

	rc = bbdd_poll_set_fd(pctx, ctl->fd, POLLIN,
			      bbdd_sock_listen_accept_cb, ctl, error);
	if (rc != 0) {
		free(st);
		ctl->peer = NULL;
		return -1;
	}
	return 0;
}

/* Best-effort: switch the fd back to blocking and write the rest of the
 * TX buffer. Used at shutdown so the last response (e.g. to `stop')
 * actually reaches the client. */
static void bbdd_sock_peer_flush_blocking(struct bbdd_sock_peer *peer)
{
	int flags;

	if (peer->tx_pos >= peer->tx_len)
		return;

	flags = fcntl(peer->fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(peer->fd, F_SETFL, flags & ~O_NONBLOCK);

	while (peer->tx_pos < peer->tx_len) {
		ssize_t n = send(peer->fd, peer->tx_buf + peer->tx_pos,
				 peer->tx_len - peer->tx_pos, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		peer->tx_pos += (size_t)n;
	}
}

void bbdd_sock_listen_close_peers(struct bbdd_sock *ctl)
{
	struct bbdd_sock_listener_state *st;
	struct bbdd_sock_peer *peer, *tmp;

	if (ctl->peer == NULL)
		return;
	st = (struct bbdd_sock_listener_state *) ctl->peer;

	DL_FOREACH_SAFE(st->peers, peer, tmp) {
		DL_DELETE(st->peers, peer);
		if (peer->pctx != NULL)
			bbdd_poll_unset_fd(peer->pctx, peer->fd);
		bbdd_sock_peer_flush_blocking(peer);
		close(peer->fd);
		bbdd_sock_peer_free(peer);
	}

	if (st->pctx != NULL)
		bbdd_poll_unset_fd(st->pctx, ctl->fd);
}

static struct bbdd_sock_peer *bbdd_sock_is_stream(struct bbdd_sock *sock)
{
	struct bbdd_sock_peer *peer = sock->peer;

	/* peer is NULL only on a non-stream socket. */
	assert(peer != NULL);
	return peer;
}

int bbdd_sock_recv_obj(struct bbdd_sock *sock,
		       struct json_object **obj_out, char **error)
{
	struct bbdd_sock_peer *peer = bbdd_sock_get_peer(sock);
	char buf[4096];

	for (;;) {
		struct json_object *obj;
		ssize_t n;
		int err;

		n = read(peer->fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			bbdd_util_fmterr(error, "read: %m");
			return -1;
		}
		if (n == 0) {
			bbdd_util_fmterr(error, "Peer closed connection");
			return -1;
		}

		obj = json_tokener_parse_ex(peer->tok, buf, (int) n);
		err = json_tokener_get_error(peer->tok);

		if (obj == NULL && err == json_tokener_continue)
			continue;

		if (obj == NULL) {
			bbdd_util_fmterr(error, "JSON parse error: %s",
					 json_tokener_error_desc(err));
			return -1;
		}

		/* Note: leftover bytes after the parse are dropped here. The
		 * synchronous client path expects exactly one response per
		 * request. */
		json_tokener_reset(peer->tok);
		*obj_out = obj;
		return 0;
	}
}

int bbdd_sock_drain_into(struct bbdd_sock *sock,
			 void (*dispatch)(struct json_object *obj, void *data),
			 void *data, char **error)
{
	struct bbdd_sock_peer *peer = bbdd_sock_get_peer(sock);
	bool got_eof = false;
	int rc;

	rc = bbdd_sock_peer_read_some(peer, dispatch, data, &got_eof, error);
	if (rc != 0)
		return rc;
	if (got_eof)
		return 0;
	return 1;
}
