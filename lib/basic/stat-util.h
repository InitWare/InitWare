/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "macro.h"
#include "siphash24.h"

int stat_verify_regular(const struct stat *st);
int fd_verify_regular(int fd);

int stat_verify_linked(const struct stat *st);

bool null_or_empty(struct stat *st) _pure_;
int null_or_empty_path_with_root(const char *fn, const char *root);

int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);
static inline int inode_same(const char *filea, const char *fileb, int flags) {
        return inode_same_at(AT_FDCWD, filea, AT_FDCWD, fileb, flags);
}

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx);

#  define STRUCT_STATX_DEFINE(var)              \
        struct statx var
#  define STRUCT_NEW_STATX_DEFINE(var)          \
        union {                                 \
                struct statx sx;                \
                struct new_statx nsx;           \
        } var

int fd_is_temporary_fs(int fd);
int fd_is_network_fs(int fd);

void inode_hash_func(const struct stat *q, struct siphash *state);
int inode_compare_func(const struct stat *a, const struct stat *b);
extern const struct hash_ops inode_hash_ops;
