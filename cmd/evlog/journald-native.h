/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#ifndef JOURNALD_NATIVE_H_
#define JOURNALD_NATIVE_H_

#include "journald-server.h"

void server_process_native_message(Server *s, const void *buffer, size_t buffer_size,
    struct socket_ucred *ucred, struct timeval *tv, const char *label, size_t label_len);

void server_process_native_file(Server *s, int fd, struct socket_ucred *ucred, struct timeval *tv,
    const char *label, size_t label_len);

int server_open_native_socket(Server *s);


#endif /* JOURNALD_NATIVE_H_ */
