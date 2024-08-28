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

#include <sys/types.h>
#include <stdio.h>

#include "memstream-util.h"
#include "sd-bus.h"
#include "ordered-set.h"

struct introspect {
        MemStream m;
        char *interface_name;
        bool trusted;
};

int introspect_begin(struct introspect *i, bool trusted);
int introspect_write_default_interfaces(struct introspect *i, bool object_manager);
int introspect_write_child_nodes(struct introspect *i, OrderedSet *s, const char *prefix);
int introspect_write_interface(
                struct introspect *i,
                const char *interface_name,
                const sd_bus_vtable *v);
int introspect_finish(struct introspect *i, char **ret);
void introspect_done(struct introspect *i);
