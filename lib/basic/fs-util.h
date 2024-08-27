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
#include "lock-util.h"
#include "macro.h"

int stat_warn_permissions(const char *path, const struct stat *st);

int symlinkat_atomic_full(const char *from, int atfd, const char *to, bool make_relative);
static inline int symlink_atomic(const char *from, const char *to) {
        return symlinkat_atomic_full(from, AT_FDCWD, to, false);
}

int mknodat_atomic(int atfd, const char *path, mode_t mode, dev_t dev);
static inline int mknod_atomic(const char *path, mode_t mode, dev_t dev) {
        return mknodat_atomic(AT_FDCWD, path, mode, dev);
}

int mkfifoat_atomic(int dir_fd, const char *path, mode_t mode);
static inline int mkfifo_atomic(const char *path, mode_t mode) {
        return mkfifoat_atomic(AT_FDCWD, path, mode);
}

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

typedef enum XOpenFlags {
        XO_LABEL     = 1 << 0,
        XO_SUBVOLUME = 1 << 1,
} XOpenFlags;

int open_mkdir_at_full(int dirfd, const char *path, int flags, XOpenFlags xopen_flags, mode_t mode);
static inline int open_mkdir_at(int dirfd, const char *path, int flags, mode_t mode) {
        return open_mkdir_at_full(dirfd, path, flags, 0, mode);
}

int xopenat_full(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode);
static inline int xopenat(int dir_fd, const char *path, int open_flags) {
        return xopenat_full(dir_fd, path, open_flags, 0, 0);
}

int xopenat_lock_full(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode, LockType locktype, int operation);
static inline int xopenat_lock(int dir_fd, const char *path, int open_flags, LockType locktype, int operation) {
        return xopenat_lock_full(dir_fd, path, open_flags, 0, 0, locktype, operation);
}
