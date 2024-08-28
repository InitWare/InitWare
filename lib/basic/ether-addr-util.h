#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen

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

#include <linux/if_infiniband.h>
#include <net/ethernet.h>

#include "in-addr-util.h"
#include "memory-util.h"

/* This is MAX_ADDR_LEN as defined in linux/netdevice.h, but net/if_arp.h
 * defines a macro of the same name with a much lower size. */
#define HW_ADDR_MAX_SIZE 32

struct hw_addr_data {
        size_t length;
        union {
                struct ether_addr ether;
                uint8_t infiniband[INFINIBAND_ALEN];
                struct in_addr in;
                struct in6_addr in6;
                uint8_t bytes[HW_ADDR_MAX_SIZE];
        };
};

#define ETHER_ADDR_FORMAT_STR "%02X%02X%02X%02X%02X%02X"
#define ETHER_ADDR_FORMAT_VAL(x)                                               \
	(x).ether_addr_octet[0], (x).ether_addr_octet[1],                      \
		(x).ether_addr_octet[2], (x).ether_addr_octet[3],              \
		(x).ether_addr_octet[4], (x).ether_addr_octet[5]

static inline bool hw_addr_is_null(const struct hw_addr_data *addr) {
        assert(addr);
        return addr->length == 0 || memeqzero(addr->bytes, addr->length);
}

int ether_addr_compare(const struct ether_addr *a, const struct ether_addr *b);
static inline bool ether_addr_equal(const struct ether_addr *a, const struct ether_addr *b) {
        return ether_addr_compare(a, b) == 0;
}

#define ETHER_ADDR_NULL ((const struct ether_addr){})

static inline bool ether_addr_is_null(const struct ether_addr *addr) {
        return ether_addr_equal(addr, &ETHER_ADDR_NULL);
}
