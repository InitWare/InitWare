/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "macro.h"
#include "siphash24.h"

#include "missing.h"

#include "svc-config.h"

#ifdef SVC_HAVE_statfs
#include <sys/statfs.h>
#endif

int stat_verify_regular(const struct stat *st);
int fd_verify_regular(int fd);

int stat_verify_directory(const struct stat *st);

int stat_verify_linked(const struct stat *st);
int fd_verify_linked(int fd);

bool null_or_empty(struct stat *st) _pure_;
int null_or_empty_path_with_root(const char *fn, const char *root);

int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);
static inline int inode_same(const char *filea, const char *fileb, int flags) {
        return inode_same_at(AT_FDCWD, filea, AT_FDCWD, fileb, flags);
}
static inline int fd_inode_same(int fda, int fdb) {
        return inode_same_at(fda, NULL, fdb, NULL, AT_EMPTY_PATH);
}

#ifdef SVC_HAVE_statfs
/* The .f_type field of struct statfs is really weird defined on
 * different archs. Let's give its type a name. */
typedef typeof(((struct statfs*)NULL)->f_type) statfs_f_type_t;

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) _pure_;
int is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value);
static inline int fd_is_fs_type(int fd, statfs_f_type_t magic_value) {
        return is_fs_type_at(fd, NULL, magic_value);
}
static inline int path_is_fs_type(const char *path, statfs_f_type_t magic_value) {
        return is_fs_type_at(AT_FDCWD, path, magic_value);
}
#endif

/* Because statfs.t_type can be int on some architectures, we have to cast
 * the const magic to the type, otherwise the compiler warns about
 * signed/unsigned comparison, because the magic can be 32 bit unsigned.
 */
#define F_TYPE_EQUAL(a, b) (a == (typeof(a)) b)

int proc_mounted(void);

bool stat_inode_same(const struct stat *a, const struct stat *b);

bool statx_inode_same(const struct statx *a, const struct statx *b);
bool statx_mount_same(const struct new_statx *a, const struct new_statx *b);

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx);

#ifdef SVC_HAVE_statfs
int xstatfsat(int dir_fd, const char *path, struct statfs *ret);
#endif

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

const char* inode_type_to_string(mode_t m);
mode_t inode_type_from_string(const char *s);

static inline bool stat_is_set(const struct stat *st) {
        return st && st->st_dev != 0 && st->st_mode != MODE_INVALID;
}
static inline bool statx_is_set(const struct statx *sx) {
        return sx && sx->stx_mask != 0;
}
static inline bool new_statx_is_set(const struct new_statx *sx) {
        return sx && sx->stx_mask != 0;
}
