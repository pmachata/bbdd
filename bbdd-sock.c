// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd-sock.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/types.h>

#include "bfddp_packet.h"

static int bbdd_sock_parse_range(const char *str, long long *ret,
				 long long min, long long max,
				 const char *what)
{
	char *nulbyte;
	long long rv;

	errno = 0;
	rv = strtoll(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
	invalid:
		fprintf(stderr, "Invalid %s `%s'. Expected integral [%lld,%lld].\n",
			what, str, min, max);
		return -1;
	}
	/* Invalid number range. */
	if (rv < min || rv > max || errno == ERANGE)
		goto invalid;

	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "Invalid %s: value `%lld' followed by garbage.\n",
			what, rv);
		return -1;
	}

	*ret = rv;
	return 0;
}

int bbdd_sock_parse_u8(const char *str, uint8_t *ret, const char *what)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 0, UINT8_MAX, what);
	if (err)
		return err;

	*ret = (uint8_t) v;
	return 0;
}

int bbdd_sock_parse_u32(const char *str, uint32_t *ret, const char *what)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 0, UINT32_MAX, what);
	if (err)
		return err;

	*ret = (uint32_t) v;
	return 0;
}

static int bbdd_sock_parse_port(const char *str, uint16_t *ret_port)
{
	long long v;
	int err;

	err = bbdd_sock_parse_range(str, &v, 1, 65534, "port number");
	if (err)
		return err;

	*ret_port = (uint16_t) v;
	return 0;
}

static int bbdd_sock_parse_addr_unix(const char *sockdir,
				     const char *addr,
				     struct bbdd_sockaddr *bsa)
{
	const char *maybe_slash = "/";
	int len;

	if (sockdir[0] == '0' || sockdir[strlen(sockdir) - 1] == '/')
		maybe_slash++;

	bsa->len = sizeof(bsa->sun);
	bsa->sun.sun_family = AF_UNIX;
	len = snprintf(bsa->sun.sun_path, sizeof(bsa->sun.sun_path),
		       "%s%s%s", sockdir, maybe_slash, addr);
	if (len < 0)
		return len;
	if ((unsigned) len >= sizeof(bsa->sun.sun_path))
		return -ENOBUFS;

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
		if (asprintf(error, "Invalid address family `%d'", af) < 0)
			*error = NULL;
		return -1;
	}

	if (asprintf(error, "Invalid address: `%s'", addr) < 0)
		*error = NULL;
	return -1;
}

static int __bbdd_inet_pton(int af, const char *restrict addr,
			    void *restrict dst)
{
	char *error;
	int rc;

	rc = bbdd_inet_pton(af, addr, dst, &error);
	if (rc != 0) {
		fprintf(stderr, "%s.\n",
			error ?: "Couldn't parse address");
		free(error);
	}

	return rc;
}

static int bbdd_sock_parse_addr_ipv4(const char *addr_in,
				     struct bbdd_sockaddr *bsa)
{
	uint16_t port_num = BFD_DATA_PLANE_DEFAULT_PORT;
	char *addr;
	char *port;
	int rc;

	addr = strdupa(addr_in);

	port = strchr(addr, ':');
	if (port != NULL) {
		*port++ = '\0';
		rc = bbdd_sock_parse_port(port, &port_num);
		if (rc != 0)
			return rc;
	}

	bsa->len = sizeof(bsa->sin);
	bsa->sin.sin_family = AF_INET;
	bsa->sin.sin_port = htons(port_num);
	return __bbdd_inet_pton(AF_INET, addr, &bsa->sin.sin_addr);
}

static int bbdd_sock_parse_addr_ipv6(const char *addr_in,
				     struct bbdd_sockaddr *bsa)
{
	uint16_t port_num = BFD_DATA_PLANE_DEFAULT_PORT;
	char *addr;
	char *saux;
	int rc;

	/* Check & skip '['. */
	if (*addr_in++ != '[') {
	no_brackets:
		fprintf(stderr, "IPv6 address needs to be []-enclosed.\n");
		return -1;
	}

	addr = strdupa(addr_in);

	/* Check ']' and ... */
	saux = strrchr(addr, ']');
	if (saux == NULL)
		goto no_brackets;
	*saux++ = '\0'; /* ... terminate the address string. */

	/* Check & skip ':', parse port if any. */
	if (*saux == ':') {
		saux++;
		rc = bbdd_sock_parse_port(saux, &port_num);
		if (rc != 0)
			return rc;
	} else if (*saux != '\0') {
		fprintf(stderr, "Invalid address `%s': Garbage after closing bracket.\n",
			addr_in);
		return -1;
	}

	bsa->len = sizeof(bsa->sin6);
	bsa->sin6.sin6_family = AF_INET6;
	bsa->sin6.sin6_port = htons(port_num);
	return __bbdd_inet_pton(AF_INET6, addr, &bsa->sin6.sin6_addr);
}

int bbdd_sock_parse_addr(const char *arg, struct bbdd_sockaddr *bsa)
{
	const char *colon;
	const char *addr;
	size_t type_len;

	colon = strchr(arg, ':');
	if (colon == NULL) {
		fprintf(stderr, "Invalid address format: %s\n", arg);
		return -1;
	}

	type_len = (size_t)(colon - arg);
	addr = colon + 1;

	memset(bsa, 0, sizeof(*bsa));

	if (strncmp(arg, "unix", type_len) == 0)
		return bbdd_sock_parse_addr_unix("", addr, bsa);

	else if (strncmp(arg, "ipv4", type_len) == 0)
		return bbdd_sock_parse_addr_ipv4(addr, bsa);

	else if (strncmp(arg, "ipv6", type_len) == 0)
		return bbdd_sock_parse_addr_ipv6(addr, bsa);

	fprintf(stderr, "invalid BFD data plane socket type in `%s'\n", arg);
	return -1;
}

static int bbdd_ctl_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *ctl_bsa)
{
	return bbdd_sock_parse_addr_unix(sockdir, "bbdd.ctl", ctl_bsa);
}

static int bbdd_cli_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *cli_bsa)
{
	char *sockname;
	int rc;

	rc = asprintf(&sockname, "bbdd.cli.%d", getpid());
	if (rc < 0)
		return rc;

	rc = bbdd_sock_parse_addr_unix(sockdir, sockname, cli_bsa);
	free(sockname);
	return rc;
}

static int bbdd_sock_open_sa_nobind(const struct bbdd_sockaddr *bsa,
				    int type, struct bbdd_sock *sock)
{
	int fd;

	*sock = (struct bbdd_sock) { .fd = -1 };

	fd = socket(bsa->sa.sa_family, type, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to open socket: %m\n");
		return -1;
	}

	*sock = (struct bbdd_sock) {
		.fd = fd,
		.sa = *bsa,
	};

	return 0;
}

static void bbdd_sock_close(struct bbdd_sock *sock)
{
	close(sock->fd);
	unlink(sock->sa.sun.sun_path);
}

static int bbdd_sock_open_sa(const struct bbdd_sockaddr *bsa, int type,
			     struct bbdd_sock *sock)
{
	int rc;

	if (bsa->sa.sa_family != AF_LOCAL)
		return -1;

	unlink(bsa->sun.sun_path);

	rc = bbdd_sock_open_sa_nobind(bsa, type, sock);
	if (rc != 0)
		return rc;

	rc = bind(sock->fd, &bsa->sa, bsa->len);
	if (rc < 0) {
		fprintf(stderr, "Failed to bind socket `%s': %m\n",
			bsa->sun.sun_path);
		goto close_sock;
	}

	return 0;

close_sock:
	bbdd_sock_close(sock);
	return rc;
}

int bbdd_sock_open_d(struct bbdd_sock *ctl, const char *sockdir)
{
	struct bbdd_sockaddr bsa;
	int rc;

	rc = bbdd_ctl_sockaddr(sockdir, &bsa);
	if (rc != 0)
		return rc;

	return bbdd_sock_open_sa(&bsa, SOCK_DGRAM, ctl);
}

void bbdd_sock_close_d(struct bbdd_sock *ctl)
{
	bbdd_sock_close(ctl);
}

int bbdd_sock_open_c(struct bbdd_sock *cli,
		     struct bbdd_sock *peer,
		     const char *sockdir)
{
	struct bbdd_sockaddr ctl_bsa;
	struct bbdd_sockaddr cli_bsa;
	int rc;

	rc = bbdd_ctl_sockaddr(sockdir, &ctl_bsa);
	if (rc != 0)
		return rc;

	rc = bbdd_cli_sockaddr(sockdir, &cli_bsa);
	if (rc != 0)
		return rc;

	rc = bbdd_sock_open_sa(&cli_bsa, SOCK_DGRAM, cli);
	if (rc != 0)
		return rc;

	*peer = (struct bbdd_sock) {
		.fd = cli->fd,
		.sa = ctl_bsa,
	};
	rc = connect(peer->fd, &peer->sa.sa, peer->sa.len);
	if (rc != 0) {
		fprintf(stderr, "Failed to connect to socket `%s': %m\n",
			peer->sa.sun.sun_path);
		goto close_cli;
	}

	return 0;

close_cli:
	bbdd_sock_close_c(cli);
	return -1;

}

void bbdd_sock_close_c(struct bbdd_sock *cli)
{
	bbdd_sock_close(cli);
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
		if (asprintf(error, "bbdd_sock_open_udp: family `%d' not supported",
			     addr.sa.sa_family) < 0)
			*error = NULL;
		return -1;
	}

	fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		if (asprintf(error, "socket(af=%d, SOCK_DGRAM): %s",
			     addr.sa.sa_family, strerror(errno)) < 0)
			*error = NULL;
		return -1;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (rc < 0) {
		if (asprintf(error, "SO_REUSEADDR: %s", strerror(errno)) < 0)
			*error = NULL;
		goto close_fd;
	}

	if (addr.sa.sa_family == AF_INET6) {
		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				&one, sizeof(one));
		if (rc < 0) {
			if (asprintf(error, "IPV6_V6ONLY: %s",
				     strerror(errno)) < 0)
				*error = NULL;
			goto close_fd;
		}
	}

	rc = bind(fd, &addr.sa, addr.len);
	if (rc < 0) {
		if (asprintf(error, "bind: %s", strerror(errno)) < 0)
			*error = NULL;
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

int bbdd_sock_recv(struct bbdd_sock *sock, struct bbdd_sock *peer,
		   char **bufp)
{
	ssize_t msgsz;
	char *buf;
	ssize_t n;
	int rc;

	*bufp = NULL;
	*peer = (struct bbdd_sock) {
		.fd = sock->fd,
		.sa = {
			.len = sizeof(peer->sa),
		},
	};
	msgsz = recvfrom(sock->fd, NULL, 0, MSG_PEEK | MSG_TRUNC,
			 (struct sockaddr *) &peer->sa, &peer->sa.len);
	if (msgsz < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		return -1;
	}

	buf = calloc(1, (size_t)msgsz + 1);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate control message buffer: %m\n");
		return -1;
	}

	n = recv(sock->fd, buf, (size_t)msgsz, 0);
	if (n < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		rc = -1;
		goto out;
	}
	buf[n] = '\0';

	*bufp = buf;
	buf = NULL;
	rc = 0;

out:
	free(buf);
	return rc;
}

int bbdd_sock_sndbufsz(struct bbdd_sock *sock, size_t *p_sndbufsz)
{
	unsigned int sndbufsz = 0;
	socklen_t optlen;
	int rc;

	optlen = sizeof(sndbufsz);
	rc = getsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &sndbufsz, &optlen);
	if (rc != 0)
		return rc;

	*p_sndbufsz = sndbufsz;
	return 0;
}
