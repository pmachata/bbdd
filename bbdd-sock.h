/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

struct bbdd_sockaddr {
	union {
		struct sockaddr sa;
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

int bbdd_inet_pton(int af, const char *restrict addr, void *restrict dst,
		   char **error);
int bbdd_sock_parse_addr(const char *arg, struct bbdd_sockaddr *sa);

int bbdd_sock_open_d(struct bbdd_sock *ctl, const char *sockdir);
void bbdd_sock_close_d(struct bbdd_sock *ctl);

int bbdd_sock_open_c(struct bbdd_sock *cli,
		     struct bbdd_sock *peer,
		     const char *sockdir);
void bbdd_sock_close_c(struct bbdd_sock *cli);

int bbdd_sock_recv(struct bbdd_sock *sock,
		   struct bbdd_sock *peer,
		   char **bufp);
int bbdd_sock_sndbufsz(struct bbdd_sock *sock, size_t *p_sndbufsz);
