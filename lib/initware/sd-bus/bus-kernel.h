#pragma once

#include "sd-bus.h"

#define MEMFD_CACHE_MAX 32

/* When we cache a memfd block for reuse, we will truncate blocks
 * longer than this in order not to keep too much data around. */
#define MEMFD_CACHE_ITEM_SIZE_MAX (128*1024)

/* This determines at which minimum size we prefer sending memfds over
 * sending vectors */
#define MEMFD_MIN_SIZE (512*1024)

struct memfd_cache {
        int fd;
        void *address;
        size_t mapped;
        size_t allocated;
};

uint64_t request_name_flags_to_kdbus(uint64_t sd_bus_flags);
uint64_t attach_flags_to_kdbus(uint64_t sd_bus_flags);

void close_and_munmap(int fd, void *address, size_t size);
void bus_flush_memfd(sd_bus *bus);

#if 0
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

#include "sd-bus.h"

#endif
