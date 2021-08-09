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

#ifndef JOURNALD_STREAM_H_
#define JOURNALD_STREAM_H_

#include "journald-server.h"

int server_open_stdout_socket(Server *s);

void stdout_stream_new(struct ev_loop *evloop, ev_io *watch, int revents);
void stdout_stream_free(StdoutStream *s);
void stdout_stream_process(struct ev_loop *evloop, ev_io *watch, int revents);

#endif /* JOURNALD_STREAM_H_ */
