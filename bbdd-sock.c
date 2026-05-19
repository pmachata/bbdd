// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd-sock.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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

#include "bbdd-util.h" // xxx util has drifted away from being very low-level
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
	rv = strtoll(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
	invalid:
		bbdd_util_fmterr(error, "Invalid %s `%s'. Expected integral [%lld,%lld]",
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

static int bbdd_cli_sockaddr(const char *sockdir,
			     struct bbdd_sockaddr *cli_bsa, char **error)
{
	char *sockname;
	int rc;

	rc = asprintf(&sockname, "bbdd.cli.%d", getpid());
	if (rc < 0) {
		bbdd_util_fmterr(error, "%m");
		return rc;
	}

	rc = bbdd_sock_parse_addrstr_unix(sockdir, sockname, cli_bsa, error);
	free(sockname);
	return rc;
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

	rc = bbdd_sock_open_sa(&bsa, SOCK_DGRAM, ctl, error);
	if (rc != 0)
		goto err;

	return 0;

err:
	bbdd_util_appenderr(error, "Failed to open daemon socket");
	return rc;
}

void bbdd_sock_close_d(struct bbdd_sock *ctl)
{
	bbdd_sock_close(ctl);
}

int bbdd_sock_open_c(struct bbdd_sock *cli,
		     struct bbdd_sock *peer,
		     const char *sockdir,
		     char **error)
{
	struct bbdd_sockaddr ctl_bsa;
	struct bbdd_sockaddr cli_bsa;
	int rc;

	rc = bbdd_ctl_sockaddr(sockdir, &ctl_bsa, error);
	if (rc != 0)
		return rc;

	rc = bbdd_cli_sockaddr(sockdir, &cli_bsa, error);
	if (rc != 0)
		return rc;

	rc = bbdd_sock_open_sa(&cli_bsa, SOCK_DGRAM, cli, error);
	if (rc != 0)
		return rc;

	*peer = (struct bbdd_sock) {
		.fd = cli->fd,
		.sa = ctl_bsa,
	};
	rc = connect(peer->fd, &peer->sa.sa, peer->sa.len);
	if (rc != 0) {
		bbdd_util_fmterr(error, "Failed to connect to socket `%s': %m",
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

int bbdd_sock_open_raw(sa_family_t family,
		       struct bbdd_sock *sock,
		       char **error)
{
	uint16_t ethtype;
	int one = 1;
	int fd;
	int rc;

	switch (family) {
	case AF_INET:
		ethtype = ETH_P_IP;
		break;
	case AF_INET6:
		ethtype = ETH_P_IPV6;
		break;
	default:
		bbdd_util_fmterr(error, "bbdd_sock_open_raw: family `%d' not supported",
				 family);
		return -1;
	}

	fd = socket(AF_PACKET, SOCK_RAW, htons(ethtype));
	if (fd < 0) {
		bbdd_util_fmterr(error, "socket(AF_PACKET, SOCK_RAW): %s",
				 strerror(errno));
		return -1;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (rc < 0) {
		bbdd_util_fmterr(error, "SO_REUSEADDR: %s", strerror(errno));
		goto close_fd;
	}

	*sock = (struct bbdd_sock) {
		.fd = fd,
		.sa.sa.sa_family = family,
	};
	return 0;

close_fd:
	close(fd);
	return -1;
}

void bbdd_sock_close_raw(struct bbdd_sock *sock)
{
	close(sock->fd);
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
