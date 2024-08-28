/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <sys/types.h>

#include "ether-addr-util.h"

int ether_addr_compare(const struct ether_addr *a, const struct ether_addr *b) {
        return memcmp(a, b, ETH_ALEN);
}
