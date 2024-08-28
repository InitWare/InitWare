/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "errno-util.h"

typedef enum RemoveFlags {
        REMOVE_ONLY_DIRECTORIES = 1 << 0, /* Only remove empty directories, no files */
        REMOVE_ROOT             = 1 << 1, /* Remove the specified directory itself too, not just the contents of it */
        REMOVE_PHYSICAL         = 1 << 2, /* If not set, only removes files on tmpfs, never physical file systems */
        REMOVE_SUBVOLUME        = 1 << 3, /* Drop btrfs subvolumes in the tree too */
        REMOVE_MISSING_OK       = 1 << 4, /* If the top-level directory is missing, ignore the ENOENT for it */
        REMOVE_CHMOD            = 1 << 5, /* chmod() for write access if we cannot delete or access something */
        REMOVE_CHMOD_RESTORE    = 1 << 6, /* Restore the old mode before returning */
        REMOVE_SYNCFS           = 1 << 7, /* syncfs() the root of the specified directory after removing everything in it */
} RemoveFlags;

/* Note: directory file descriptors passed to the functions below must be
 * positioned at the beginning. If the fd was already used for reading, rewind it. */
int rm_rf_children(int fd, RemoveFlags flags, const struct stat *root_dev);
int rm_rf_child(int fd, const char *name, RemoveFlags flags);
int rm_rf_at(int dir_fd, const char *path, RemoveFlags flags);
static inline int rm_rf(const char *path, RemoveFlags flags) {
        return rm_rf_at(AT_FDCWD, path, flags);
}
