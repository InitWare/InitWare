/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include "errno-util.h"
#include "sd-id128.h"

int id128_get_machine(const char *root, sd_id128_t *ret);

/* A helper to check for the three relevant cases of "machine ID not initialized" */
#define ERRNO_IS_NEG_MACHINE_ID_UNSET(r)        \
        IN_SET(r,                               \
               -ENOENT,                         \
               -ENOMEDIUM,                      \
               -ENOPKG)
_DEFINE_ABS_WRAPPER(MACHINE_ID_UNSET);
