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

#include "sd-bus.h"
#include "unit.h"

extern const sd_bus_vtable bus_scope_vtable[];

int bus_scope_set_property(Unit *u, const char *name, sd_bus_message *i,
	UnitSetPropertiesMode mode, sd_bus_error *error);
int bus_scope_commit_properties(Unit *u);

int bus_scope_send_request_stop(Scope *s);

int bus_scope_method_abandon(sd_bus_message *message, void *userdata, sd_bus_error *error);
