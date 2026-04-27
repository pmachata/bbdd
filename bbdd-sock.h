/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

/* This structure is layout-compatible with the start of struct sockaddr_in and
 * struct sockaddr_in6, but not struct sockaddr_un. */
struct bddd_sockaddr_in46 {
	sa_family_t family;
	in_port_t port;
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

struct bbdd_sock {
	int fd;
	struct bbdd_sockaddr sa;
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

/* Parse a string in format of <address> */
int bbdd_sock_parse_addr_af(int af, const char *arg, struct bbdd_sockaddr *sa,
			    char **error);

int bbdd_sock_open_d(struct bbdd_sock *ctl, const char *sockdir);
void bbdd_sock_close_d(struct bbdd_sock *ctl);

int bbdd_sock_open_c(struct bbdd_sock *cli,
		     struct bbdd_sock *peer,
		     const char *sockdir);
void bbdd_sock_close_c(struct bbdd_sock *cli);

int bbdd_sock_open_raw(sa_family_t family,
		       struct bbdd_sock *sock,
		       char **error);
void bbdd_sock_close_raw(struct bbdd_sock *sock);

int bbdd_sock_open_udp(struct bbdd_sockaddr addr,
		       struct bbdd_sock *sock,
		       char **error);
void bbdd_sock_close_udp(struct bbdd_sock *sock);

int bbdd_sock_recv(struct bbdd_sock *sock,
		   struct bbdd_sock *peer,
		   char **bufp);
int bbdd_sock_sndbufsz(struct bbdd_sock *sock, size_t *p_sndbufsz);
