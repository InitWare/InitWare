/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/ioctl.h>

#include "macro.h"
#include "util.h"
#include "mkdir.h"
#include "socket-util.h"
#include "missing.h"
#include "label.h"

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
                int *ret) {

        int r, fd, one;
        assert(a);
        assert(ret);

        if ((r = socket_address_verify(a)) < 0)
                return r;

        if (socket_address_family(a) == AF_INET6 && !socket_ipv6_is_supported())
                return -EAFNOSUPPORT;

        r = label_socket_set(label);
        if (r < 0)
                return r;

        fd = socket(socket_address_family(a), a->type, a->protocol);
        r = fd < 0 ? -errno : 0;

        label_socket_clear();

        if (r < 0)
                return r;

	r = fd_cloexec(fd, true);
	r = r < 0 ? r : fd_nonblock(fd, true);

	if (r < 0) {
		log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
		goto fail;
	}

        if (socket_address_family(a) == AF_INET6 && only != SOCKET_ADDRESS_DEFAULT) {
                int flag = only == SOCKET_ADDRESS_IPV6_ONLY;

                if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) < 0)
                        goto fail;
        }

        if (socket_address_family(a) == AF_INET || socket_address_family(a) == AF_INET6) {
#ifdef SO_BINDTODEVICE
                if (bind_to_device)
                        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bind_to_device, strlen(bind_to_device)+1) < 0)
                                goto fail;
#endif

#ifdef IP_FREEBIND
                if (free_bind) {
                        one = 1;
                        if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
                                log_warning("IP_FREEBIND failed: %m");
                }
#endif

#ifdef IP_TRANSPARENT
                if (transparent) {
                        one = 1;
                        if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one)) < 0)
                                log_warning("IP_TRANSPARENT failed: %m");
                }
#endif
        }

        one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
                goto fail;

        if (socket_address_family(a) == AF_UNIX && a->sockaddr.un.sun_path[0] != 0) {
                mode_t old_mask;

                /* Create parents */
                mkdir_parents_label(a->sockaddr.un.sun_path, directory_mode);

                /* Enforce the right access mode for the socket*/
                old_mask = umask(~ socket_mode);

                /* Include the original umask in our mask */
                umask(~socket_mode | old_mask);

                r = label_bind(fd, &a->sockaddr.sa, a->size);

                if (r < 0 && errno == EADDRINUSE) {
                        /* Unlink and try again */
                        unlink(a->sockaddr.un.sun_path);
                        r = bind(fd, &a->sockaddr.sa, a->size);
                }

                umask(old_mask);
        } else
                r = bind(fd, &a->sockaddr.sa, a->size);

        if (r < 0)
                goto fail;

        if (socket_address_can_accept(a))
                if (listen(fd, backlog) < 0)
                        goto fail;

        *ret = fd;
        return 0;

fail:
        r = -errno;
        safe_close(fd);
        return r;
}
