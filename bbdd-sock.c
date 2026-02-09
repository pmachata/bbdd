// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd-sock.h"

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

static uint16_t bbdd_sock_parse_port(const char *str)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
		fprintf(stderr, "invalid BFD HAL address port: %s\n", str);
		exit(1);
	}
	/* Invalid number range. */
	if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		fprintf(stderr, "invalid BFD HAL address port range: %s\n",
			str);
		exit(1);
	}
	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "invalid BFD HAL address port string: %s\n",
			str);
		exit(1);
	}

	return (uint16_t)rv;
}

int bbdd_sock_parse_addr(const char *arg, struct bbdd_sockaddr *bsa)
{
	const char *colon;
	size_t type_len;
	char addr[64];

	colon = strchr(arg, ':');
	if (colon == NULL) {
		fprintf(stderr, "Invalid address format: %s\n", arg);
		return -1;
	}

	type_len = (size_t)(colon - arg);

	if (strlen(colon + 1) >= sizeof(addr)) {
		fprintf(stderr, "Addr `%s' is too long\n", colon + 1);
		return -1;
	}
	strcpy(addr, colon + 1); /// xxx test me

	memset(bsa, 0, sizeof(*bsa));
	if (strncmp(arg, "unix", type_len) == 0) {
		struct sockaddr_un *sun = &bsa->sun;

		bsa->len = sizeof(*sun);
		sun->sun_family = AF_UNIX;
		snprintf(sun->sun_path, sizeof(sun->sun_path), "%s", addr);

	} else if (strncmp(arg, "ipv4", type_len) == 0) {
		struct sockaddr_in *sin = &bsa->sin;
		char *port;

		sin->sin_family = AF_INET;
		bsa->len = sizeof(*sin);

		/* Parse port if any. */
		port = strchr(addr, ':');
		if (port == NULL) {
			sin->sin_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*port++ = '\0';
			sin->sin_port = htons(bbdd_sock_parse_port(port));
		}

		inet_pton(AF_INET, addr, &sin->sin_addr);
		// xxx error check

	} else if (strncmp(arg, "ipv6", type_len) == 0) {
		struct sockaddr_in6 *sin6 = &bsa->sin6;
		char *saux, *sptr;
		size_t slen;

		sin6->sin6_family = AF_INET6;
		bsa->len = sizeof(*sin6);

		/* Check for IPv6 enclosures '[]' */
		sptr = &addr[0];
		if (*sptr != '[') {
			fprintf(stderr, "Invalid IPv6 address: `%s' (try [::1])\n",
				addr);
			return -1;
		}

		saux = strrchr(addr, ']');
		if (saux == NULL) {
			fprintf(stderr, "Invalid IPv6 address: `%s' (try [::1])",
				addr);
			return -1;
		}

		/* Consume the '[]:' part. */
		slen = (size_t)(saux - sptr);
		memmove(addr, addr + 1, slen);
		addr[slen - 1] = 0;

		/* Parse port if any. */
		saux++;
		sptr = strrchr(saux, ':');
		if (sptr == NULL) {
			sin6->sin6_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*sptr = '\0';
			sin6->sin6_port = htons(bbdd_sock_parse_port(sptr + 1));
		}

		inet_pton(AF_INET6, addr, &sin6->sin6_addr);
		// xxx error check

	} else {
		fprintf(stderr, "invalid BFD data plane socket type in `%s'\n",
			arg);
		return -1;
	}

	return 0;
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
