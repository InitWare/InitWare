/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <sys/types.h>

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}
