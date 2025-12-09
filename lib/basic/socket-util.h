#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "macro.h"
#include "util.h"

#if defined(SVC_PLATFORM_Linux)
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <netinet/ether.h>
#elif defined(SVC_PLATFORM_FreeBSD)
#include <netlink/netlink.h>
#endif

#if defined(SVC_PLATFORM_Linux)
#define CREDPASS_IMPLICIT 1
#define CREDPASS_PERSISTS 1

#define CMSG_TYPE_CREDS SCM_CREDENTIALS
#define SOCKOPT_CREDPASS_LEVEL SOL_SOCKET
#define SOCKOPT_CREDPASS_OPT SO_PASSCRED

#define CMSG_CREDS_STRUCT struct ucred
#define CMSG_CREDS_STRUCT_SIZE sizeof(struct ucred)
#define CMSG_CREDS_STRUCT_pid pid
#define CMSG_CREDS_STRUCT_uid uid
#define CMSG_CREDS_STRUCT_gid uid

#define socket_ucred ucred

#elif defined(SVC_PLATFORM_FreeBSD)
#define CREDPASS_IMPLICIT 1
#define CREDPASS_PERSISTS 1

#define CMSG_TYPE_CREDS SCM_CREDS2
#define SOCKOPT_CREDPASS_LEVEL 0
#define SOCKOPT_CREDPASS_OPT LOCAL_CREDS_PERSISTENT

#define CMSG_CREDS_STRUCT struct sockcred2
#define CMSG_CREDS_STRUCT_SIZE SOCKCRED2SIZE(NGROUPS)
#define CMSG_CREDS_STRUCT_pid sc_pid
#define CMSG_CREDS_STRUCT_uid sc_uid
#define CMSG_CREDS_STRUCT_gid sc_gid

#elif defined(SVC_PLATFORM_NetBSD)
#define CREDPASS_IMPLICIT 1

#define CMSG_TYPE_CREDS SCM_CREDS
#define SOCKOPT_CREDPASS_LEVEL 0
#define SOCKOPT_CREDPASS_OPT LOCAL_CREDS

#define CMSG_CREDS_STRUCT struct sockcred
#define CMSG_CREDS_STRUCT_SIZE SOCKCREDSIZE(NGROUPS)
#define CMSG_CREDS_STRUCT_pid sc_pid
#define CMSG_CREDS_STRUCT_uid sc_uid
#define CMSG_CREDS_STRUCT_gid sc_gid

#elif defined(SVC_PLATFORM_DragonFlyBSD)
#undef CREDPASS_IMPLICIT

#define CMSG_TYPE_CREDS SCM_CREDS

#define CMSG_CREDS_STRUCT struct cmsgcred
#define CMSG_CREDS_STRUCT_SIZE sizeof(struct cmsgcred)
#define CMSG_CREDS_STRUCT_pid cmcred_pid
#define CMSG_CREDS_STRUCT_uid cmcred_uid
#define CMSG_CREDS_STRUCT_gid cmcred_gid

#endif

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr_un un;
#ifdef SVC_PLATFORM_Linux
	struct sockaddr_nl nl;
	struct sockaddr_ll ll;
#endif
	struct sockaddr_storage storage;
};

typedef struct SocketAddress {
	union sockaddr_union sockaddr;

	/* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
	socklen_t size;

	/* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
	int type;

	/* Socket protocol, IPPROTO_xxx, usually 0, except for netlink */
	int protocol;
} SocketAddress;

typedef enum SocketAddressBindIPv6Only {
	SOCKET_ADDRESS_DEFAULT,
	SOCKET_ADDRESS_BOTH,
	SOCKET_ADDRESS_IPV6_ONLY,
	_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX,
	_SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID = -1
} SocketAddressBindIPv6Only;

#define socket_address_family(a) ((a)->sockaddr.sa.sa_family)

int socket_address_parse(SocketAddress *a, const char *s);
int socket_address_parse_and_warn(SocketAddress *a, const char *s);
int socket_address_parse_netlink(SocketAddress *a, const char *s);
int socket_address_print(const SocketAddress *a, char **p);
int socket_address_verify(const SocketAddress *a) _pure_;
int socket_address_unlink(SocketAddress *a);

bool socket_address_can_accept(const SocketAddress *a) _pure_;

int socket_address_listen(const SocketAddress *a, int flags, int backlog,
	SocketAddressBindIPv6Only only, const char *bind_to_device,
	bool free_bind, bool transparent, mode_t directory_mode,
	mode_t socket_mode, const char *label);
int make_socket_fd(int log_level, const char *address, int flags);

bool socket_address_is(const SocketAddress *a, const char *s, int type);

bool socket_address_is_netlink(const SocketAddress *a, const char *s);

bool socket_address_matches_fd(const SocketAddress *a, int fd);

bool socket_address_equal(const SocketAddress *a,
	const SocketAddress *b) _pure_;

const char *socket_address_get_path(const SocketAddress *a);

bool socket_ipv6_is_supported(void);

int sockaddr_port(const struct sockaddr *_sa) _pure_;

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen,
	bool translate_ipv6, bool include_port, char **ret);
int getpeername_pretty(int fd, bool include_port, char **ret);
int getsockname_pretty(int fd, char **ret);

int socknameinfo_pretty(union sockaddr_union *sa, socklen_t salen, char **_ret);
int getnameinfo_pretty(int fd, char **ret);

const char *socket_address_bind_ipv6_only_to_string(
	SocketAddressBindIPv6Only b) _const_;
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_from_string(
	const char *s) _pure_;

int netlink_family_to_string_alloc(int b, char **s);
int netlink_family_from_string(const char *s) _pure_;

bool sockaddr_equal(const union sockaddr_union *a,
	const union sockaddr_union *b);

#ifdef SVC_PLATFORM_Linux
#define ETHER_ADDR_TO_STRING_MAX (3 * 6)

char *ether_addr_to_string(const struct ether_addr *addr,
	char buffer[ETHER_ADDR_TO_STRING_MAX]);
#endif

int socket_passcred(int fd);
int cmsg_readucred(struct cmsghdr *cmsg, struct socket_ucred *xucred);
