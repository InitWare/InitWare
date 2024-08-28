#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"

enum {
	BUS_MESSAGE_DUMP_WITH_HEADER = 1,
	BUS_MESSAGE_DUMP_SUBTREE_ONLY = 2,
};

int bus_creds_dump(sd_bus_creds *c, FILE *f, bool terse);

int bus_pcap_header(size_t snaplen, const char *os, const char *app, FILE *f);
int bus_message_pcap_frame(sd_bus_message *m, size_t snaplen, FILE *f);
