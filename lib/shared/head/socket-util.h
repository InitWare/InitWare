#ifndef SOCKET_UTIL_H_
#define SOCKET_UTIL_H_

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
/*
 * Copyright 2021 David Mackay. All rights reserved.
 */


#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>

#include "compat.h"
#include "macro.h"
#include "util.h"

#ifdef Have_asm_types_h
#        include <asm/types.h>
#endif
#ifdef Have_linux_netlink_h
#        include <linux/netlink.h>
#endif

#ifdef SCM_CREDENTIALS
#        define SCM_CRED_OPT SCM_CREDENTIALS
#elif defined(SCM_CREDS)
#        define SCM_CRED_OPT SCM_CREDS
#endif

#ifdef Have_socket_struct_ucred
#        define socket_ucred ucred
#        define dgram_creds struct ucred
#        define dgram_creds_pid pid
#        define dgram_creds_uid uid
#        define dgram_creds_gid uid
#elif defined(Have_struct_cmsgcred)
#        define Cmsgcred
#        define dgram_creds struct cmsgcred
#        define dgram_creds_pid cmcred_pid
#        define dgram_creds_uid cmcred_uid
#        define dgram_creds_gid cmcred_gid
#endif

#ifndef Have_socket_struct_ucred
/**
 * A replica of Linux's struct ucred (an entirely inappropriate name).
 * This is reasonable conjunction of the socket peer/sender credentials we
 * expect all supported platforms to offer us.
 */
struct socket_ucred {
        pid_t pid;
        uid_t uid;
        gid_t gid;
};
#endif

union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
#ifdef Have_linux_netlink_h
        struct sockaddr_nl nl;
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
int socket_address_parse_netlink(SocketAddress *a, const char *s);
int socket_address_print(const SocketAddress *a, char **p);
int socket_address_verify(const SocketAddress *a) _pure_;

bool socket_address_can_accept(const SocketAddress *a) _pure_;

int socket_address_listen(
        const SocketAddress *a,
        int backlog,
        SocketAddressBindIPv6Only only,
        const char *bind_to_device,
        bool free_bind,
        bool transparent,
        mode_t directory_mode,
        mode_t socket_mode,
        const char *label,
        int *ret);

bool socket_address_is(const SocketAddress *a, const char *s, int type);
bool socket_address_is_netlink(const SocketAddress *a, const char *s);

bool socket_address_matches_fd(const SocketAddress *a, int fd);

int make_socket_fd(const char *address, int flags);

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) _pure_;

const char *socket_address_get_path(const SocketAddress *a);

const char *socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only b) _const_;
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_from_string(const char *s) _pure_;

#ifdef Have_linux_netlink_h
int netlink_family_to_string_alloc(int b, char **s);
int netlink_family_from_string(const char *s);
#endif

bool socket_ipv6_is_supported(void);

/** Enable receipt of credentials on a datagram socket, if supported. */
int socket_passcred(int fd);

#endif
