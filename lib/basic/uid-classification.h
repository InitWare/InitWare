/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>
#include <sys/types.h>

// HACK: Systemd does some configure time magic for these values!
#define SYSTEM_ALLOC_UID_MIN 1
#define SYSTEM_ALLOC_GID_MIN 1
#define SYSTEM_UID_MAX 999
#define SYSTEM_GID_MAX 999

bool uid_is_system(uid_t uid);
bool gid_is_system(gid_t gid);

typedef struct UGIDAllocationRange {
        uid_t system_alloc_uid_min;
        uid_t system_uid_max;
        gid_t system_alloc_gid_min;
        gid_t system_gid_max;
} UGIDAllocationRange;

const UGIDAllocationRange *acquire_ugid_allocation_range(void);
