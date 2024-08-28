/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdint.h>

typedef enum PathSimplifyWarnFlags {
        PATH_CHECK_FATAL              = 1 << 0,  /* If not set, then error message is appended with 'ignoring'. */
        PATH_CHECK_ABSOLUTE           = 1 << 1,
        PATH_CHECK_RELATIVE           = 1 << 2,
        PATH_KEEP_TRAILING_SLASH      = 1 << 3,
        PATH_CHECK_NON_API_VFS        = 1 << 4,
        PATH_CHECK_NON_API_VFS_DEV_OK = 1 << 5,
} PathSimplifyWarnFlags;

int path_simplify_and_warn(
                char *path,
                PathSimplifyWarnFlags flags,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue);
