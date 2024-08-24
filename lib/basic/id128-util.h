/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include "errno-util.h"
#include "sd-id128.h"

typedef enum Id128Flag {
        ID128_FORMAT_PLAIN  = 1 << 0,  /* formatted as 32 hex chars as-is */
        ID128_FORMAT_UUID   = 1 << 1,  /* formatted as 36 character uuid string */
        ID128_FORMAT_ANY    = ID128_FORMAT_PLAIN | ID128_FORMAT_UUID,

        ID128_SYNC_ON_WRITE = 1 << 2, /* Sync the file after write. Used only when writing an ID. */
        ID128_REFUSE_NULL   = 1 << 3, /* Refuse all zero ID with -ENOMEDIUM. */
} Id128Flag;

int id128_read_fd(int fd, Id128Flag f, sd_id128_t *ret);
int id128_read_at(int dir_fd, const char *path, Id128Flag f, sd_id128_t *ret);
static inline int id128_read(const char *path, Id128Flag f, sd_id128_t *ret) {
        return id128_read_at(AT_FDCWD, path, f, ret);
}

int id128_get_machine(const char *root, sd_id128_t *ret);

int id128_compare_func(const sd_id128_t *a, const sd_id128_t *b) _pure_;

sd_id128_t id128_make_v4_uuid(sd_id128_t id);

/* A helper to check for the three relevant cases of "machine ID not initialized" */
#define ERRNO_IS_NEG_MACHINE_ID_UNSET(r)        \
        IN_SET(r,                               \
               -ENOENT,                         \
               -ENOMEDIUM,                      \
               -ENOPKG)
_DEFINE_ABS_WRAPPER(MACHINE_ID_UNSET);
