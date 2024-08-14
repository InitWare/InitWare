/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <glob.h>
#include <stdbool.h>

#include "macro.h"
#include "string-util.h"

_pure_ static inline bool string_is_glob(const char *p) {
        /* Check if a string contains any glob patterns. */
        return !!strpbrk(p, GLOB_CHARS);
}
