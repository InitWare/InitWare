/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "macro.h"

int stat_warn_permissions(const char *path, const struct stat *st);

int get_files_in_directory(const char *path, char ***list);

int tmp_dir(const char **ret);
int var_tmp_dir(const char **ret);

int posix_fallocate_loop(int fd, uint64_t offset, uint64_t size);

/* Useful for usage with _cleanup_(), removes a directory and frees the pointer */
static inline char *rmdir_and_free(char *p) {
        PROTECT_ERRNO;

        if (!p)
                return NULL;

        (void) rmdir(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rmdir_and_free);

static inline char* unlink_and_free(char *p) {
        if (!p)
                return NULL;

        (void) unlink(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, unlink_and_free);

int access_fd(int fd, int mode);

int openat_report_new(int dirfd, const char *pathname, int flags, mode_t mode, bool *ret_newly_created);
