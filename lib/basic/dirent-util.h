/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <dirent.h>
#include <errno.h>

#include "macro.h"
#include "path-util.h"

struct dirent *readdir_ensure_type(DIR *d);

#define FOREACH_DIRENT_ALL(de, d, on_error)                             \
        for (struct dirent *(de) = readdir_ensure_type(d);; (de) = readdir_ensure_type(d)) \
                if (!de) {                                              \
                        if (errno > 0) {                                \
                                on_error;                               \
                        }                                               \
                        break;                                          \
                } else

#define FOREACH_DIRENT(de, d, on_error)                                 \
        FOREACH_DIRENT_ALL(de, d, on_error)                             \
             if (hidden_or_backup_file((de)->d_name))                   \
                     continue;                                          \
             else
