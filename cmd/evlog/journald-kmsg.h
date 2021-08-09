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

#ifndef JOURNALD_KMSG_H_
#define JOURNALD_KMSG_H_

#include "journald-server.h"

int server_open_dev_kmsg(Server *s);
int server_read_dev_kmsg(Server *s);
int server_flush_dev_kmsg(Server *s);

void server_forward_kmsg(Server *s, int priority, const char *identifier, const char *message,
    struct socket_ucred *ucred);

int server_open_kernel_seqnum(Server *s);


#endif /* JOURNALD_KMSG_H_ */