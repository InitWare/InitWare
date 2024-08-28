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

#include "bus-match.h"
#include "sd-bus.h"

int bus_add_match_internal(sd_bus *bus, const char *match, uint64_t timeout_usec, uint64_t *ret_counter);
int bus_add_match_internal_async(sd_bus *bus, sd_bus_slot **ret, const char *match, sd_bus_message_handler_t callback, void *userdata, uint64_t timeout_usec);
int bus_remove_match_internal(sd_bus *bus, const char *match);

// int bus_add_match_internal_kernel(sd_bus *bus,
// 	struct bus_match_component *components, unsigned n_components,
// 	uint64_t cookie);
// int bus_remove_match_internal_kernel(sd_bus *bus, uint64_t cookie);

// int bus_get_name_creds_kdbus(sd_bus *bus, const char *name, uint64_t mask,
// 	bool allow_activator, sd_bus_creds **creds);
