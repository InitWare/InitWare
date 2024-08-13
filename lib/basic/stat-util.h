/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <sys/stat.h>

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx);

#  define STRUCT_STATX_DEFINE(var)              \
        struct statx var
#  define STRUCT_NEW_STATX_DEFINE(var)          \
        union {                                 \
                struct statx sx;                \
                struct new_statx nsx;           \
        } var
