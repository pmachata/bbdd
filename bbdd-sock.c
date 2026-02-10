// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd-sock.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/types.h>

#include "bfddp_packet.h"

static int bbdd_sock_parse_port(const char *str, uint16_t *ret_port)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
	invalid:
		fprintf(stderr, "Invalid port number `%s'. Expected integral [0,63353].\n",
			str);
		return -1;
	}
	/* Invalid number range. */
	if (rv <= 0 || rv >= 65535 || errno == ERANGE)
		goto invalid;

	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "Invalid port number: value `%ld' followed by garbage.\n",
			rv);
		return -1;
	}

	*ret_port = (uint16_t)rv;
	return 0;
}

static int bbdd_sock_parse_addr_unix(const char *addr,
				     struct bbdd_sockaddr *bsa)
{
	if (strlen(addr) >= sizeof(bsa->sun.sun_path))
		return -ENOBUFS;

	bsa->len = sizeof(bsa->sun);
	bsa->sun.sun_family = AF_UNIX;
	snprintf(bsa->sun.sun_path, sizeof(bsa->sun.sun_path), "%s", addr);
	return 0;
}

static int bbdd_inet_pton(int af, const char *restrict addr, void *restrict dst)
{
	int rc;

	rc = inet_pton(af, addr, dst);
	if (rc == 1)
		return 0;

	assert(rc != -1); /* AF ought to be valid! */
	fprintf(stderr, "Invalid address: `%s'.\n", addr);
	return -1;
}

static int bbdd_sock_parse_addr_ipv4(const char *addr_in,
				     struct bbdd_sockaddr *bsa)
{
	uint16_t port_num = BFD_DATA_PLANE_DEFAULT_PORT;
	char *addr;
	char *port;
	int err;

	addr = strdupa(addr_in);

	port = strchr(addr, ':');
	if (port != NULL) {
		*port++ = '\0';
		err = bbdd_sock_parse_port(port, &port_num);
		if (err != 0)
			return err;
	}

	bsa->len = sizeof(bsa->sin);
	bsa->sin.sin_family = AF_INET;
	bsa->sin.sin_port = htons(port_num);
	return bbdd_inet_pton(AF_INET, addr, &bsa->sin.sin_addr);
}

static int bbdd_sock_parse_addr_ipv6(const char *addr_in,
				     struct bbdd_sockaddr *bsa)
{
	uint16_t port_num = BFD_DATA_PLANE_DEFAULT_PORT;
	char *addr;
	char *saux;
	int err;

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
		err = bbdd_sock_parse_port(saux, &port_num);
		if (err != 0)
			return err;
	} else if (*saux != '\0') {
		fprintf(stderr, "Invalid address `%s': Garbage after closing bracket.\n",
			addr_in);
		return -1;
	}

	bsa->len = sizeof(bsa->sin6);
	bsa->sin6.sin6_family = AF_INET6;
	bsa->sin6.sin6_port = htons(port_num);
	return bbdd_inet_pton(AF_INET6, addr, &bsa->sin6.sin6_addr);
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
		return bbdd_sock_parse_addr_unix(addr, bsa);

	else if (strncmp(arg, "ipv4", type_len) == 0)
		return bbdd_sock_parse_addr_ipv4(addr, bsa);

	else if (strncmp(arg, "ipv6", type_len) == 0)
		return bbdd_sock_parse_addr_ipv6(addr, bsa);

	fprintf(stderr, "invalid BFD data plane socket type in `%s'\n", arg);
	return -1;
}

static int bbdd_sock_sockaddr(const char *sockdir, const char *sockname,
			      struct bbdd_sockaddr *bsa)
{
	const char *maybe_slash = "/";
	int len;

	if (sockdir[strlen(sockdir) - 1] == '/' || sockname[0] == '\0')
		maybe_slash++;

	bsa->sun.sun_family = AF_LOCAL;
	bsa->len = sizeof bsa->sun;
	len = snprintf(bsa->sun.sun_path, sizeof(bsa->sun.sun_path),
		       "%s%s%s", sockdir, maybe_slash, sockname);
	if (len < 0)
		return len;
	if ((unsigned) len >= sizeof(bsa->sun.sun_path))
		return -ENOBUFS;

	return 0;
}

static int bbdd_ctl_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *ctl_bsa)
{
	return bbdd_sock_sockaddr(sockdir, "bbdd.ctl", ctl_bsa);
}

static int bbdd_cli_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *cli_bsa)
{
	char *sockname;
	int rc;

	rc = asprintf(&sockname, "bbdd.cli.%d", getpid());
	if (rc < 0)
		return rc;

	rc = bbdd_sock_sockaddr(sockdir, sockname, cli_bsa);
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
