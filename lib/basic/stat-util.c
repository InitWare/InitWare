/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/magic.h>

#include "errno-util.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "stat-util.h"

#include "svc-config.h"

#ifdef HAVE_sys_sysmacros_h
#include <sys/sysmacros.h>
#endif

void inode_hash_func(const struct stat *q, struct siphash *state) {
        siphash24_compress_typesafe(q->st_dev, state);
        siphash24_compress_typesafe(q->st_ino, state);
}

int inode_compare_func(const struct stat *a, const struct stat *b) {
        int r;

        r = CMP(a->st_dev, b->st_dev);
        if (r != 0)
                return r;

        return CMP(a->st_ino, b->st_ino);
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(inode_hash_ops, struct stat, inode_hash_func, inode_compare_func, free);

#ifdef SVC_HAVE_statfs
bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) {
        assert(s);
        assert_cc(sizeof(statfs_f_type_t) >= sizeof(s->f_type));

        return F_TYPE_EQUAL(s->f_type, magic_value);
}

int is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value) {
        struct statfs s;
        int r;

        r = xstatfsat(dir_fd, path, &s);
        if (r < 0)
                return r;

        return is_fs_type(&s, magic_value);
}
#endif

int proc_mounted(void) {
        int r;

        /* A quick check of procfs is properly mounted */

        r = path_is_fs_type("/proc/", PROC_SUPER_MAGIC);
        if (r == -ENOENT) /* not mounted at all */
                return false;

        return r;
}

bool stat_inode_same(const struct stat *a, const struct stat *b) {

        /* Returns if the specified stat structure references the same (though possibly modified) inode. Does
         * a thorough check, comparing inode nr, backing device and if the inode is still of the same type. */

        return stat_is_set(a) && stat_is_set(b) &&
                ((a->st_mode ^ b->st_mode) & S_IFMT) == 0 &&  /* same inode type */
                a->st_dev == b->st_dev &&
                a->st_ino == b->st_ino;
}

bool statx_inode_same(const struct statx *a, const struct statx *b) {

        /* Same as stat_inode_same() but for struct statx */

        return statx_is_set(a) && statx_is_set(b) &&
                FLAGS_SET(a->stx_mask, STATX_TYPE|STATX_INO) && FLAGS_SET(b->stx_mask, STATX_TYPE|STATX_INO) &&
                ((a->stx_mode ^ b->stx_mode) & S_IFMT) == 0 &&
                a->stx_dev_major == b->stx_dev_major &&
                a->stx_dev_minor == b->stx_dev_minor &&
                a->stx_ino == b->stx_ino;
}

bool statx_mount_same(const struct new_statx *a, const struct new_statx *b) {
        if (!new_statx_is_set(a) || !new_statx_is_set(b))
                return false;

        /* if we have the mount ID, that's all we need */
        if (FLAGS_SET(a->stx_mask, STATX_MNT_ID) && FLAGS_SET(b->stx_mask, STATX_MNT_ID))
                return a->stx_mnt_id == b->stx_mnt_id;

        /* Otherwise, major/minor of backing device must match */
        return a->stx_dev_major == b->stx_dev_major &&
                a->stx_dev_minor == b->stx_dev_minor;
}

static bool is_statx_fatal_error(int err, int flags) {
        assert(err < 0);

        /* If statx() is not supported or if we see EPERM (which might indicate seccomp filtering or so),
         * let's do a fallback. Note that on EACCES we'll not fall back, since that is likely an indication of
         * fs access issues, which we should propagate. */
        if (ERRNO_IS_NOT_SUPPORTED(err) || err == -EPERM)
                return false;

        /* When unsupported flags are specified, glibc's fallback function returns -EINVAL.
         * See statx_generic() in glibc. */
        if (err != -EINVAL)
                return true;

        if ((flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | AT_STATX_SYNC_AS_STAT)) != 0)
                return false; /* Unsupported flags are specified. Let's try to use our implementation. */

        return true;
}

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx) {
        static bool avoid_statx = false;
        struct stat st;
        int r;

        if (!avoid_statx) {
                r = RET_NERRNO(statx(dfd, path, flags, mask, sx));
                if (r >= 0 || is_statx_fatal_error(r, flags))
                        return r;

                avoid_statx = true;
        }

        /* Only do fallback if fstatat() supports the flag too, or if it's one of the sync flags, which are
         * OK to ignore */
        if ((flags & ~(AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW|
                      AT_STATX_SYNC_AS_STAT|AT_STATX_FORCE_SYNC|AT_STATX_DONT_SYNC)) != 0)
                return -EOPNOTSUPP;

        if (fstatat(dfd, path, &st, flags & (AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW)) < 0)
                return -errno;

        *sx = (struct statx) {
                .stx_mask = STATX_TYPE|STATX_MODE|
                STATX_NLINK|STATX_UID|STATX_GID|
                STATX_ATIME|STATX_MTIME|STATX_CTIME|
                STATX_INO|STATX_SIZE|STATX_BLOCKS,
                .stx_blksize = st.st_blksize,
                .stx_nlink = st.st_nlink,
                .stx_uid = st.st_uid,
                .stx_gid = st.st_gid,
                .stx_mode = st.st_mode,
                .stx_ino = st.st_ino,
                .stx_size = st.st_size,
                .stx_blocks = st.st_blocks,
                .stx_rdev_major = major(st.st_rdev),
                .stx_rdev_minor = minor(st.st_rdev),
                .stx_dev_major = major(st.st_dev),
                .stx_dev_minor = minor(st.st_dev),
                .stx_atime.tv_sec = st.st_atim.tv_sec,
                .stx_atime.tv_nsec = st.st_atim.tv_nsec,
                .stx_mtime.tv_sec = st.st_mtim.tv_sec,
                .stx_mtime.tv_nsec = st.st_mtim.tv_nsec,
                .stx_ctime.tv_sec = st.st_ctim.tv_sec,
                .stx_ctime.tv_nsec = st.st_ctim.tv_nsec,
        };

        return 0;
}

#ifdef SVC_HAVE_statfs
int xstatfsat(int dir_fd, const char *path, struct statfs *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        fd = xopenat(dir_fd, path, O_PATH|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return fd;

        return RET_NERRNO(fstatfs(fd, ret));
}
#endif
