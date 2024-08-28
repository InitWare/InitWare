/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "fileio.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"

/* This is the original MAX_HANDLE_SZ definition from the kernel, when the API was introduced. We use that in place of
 * any more currently defined value to future-proof things: if the size is increased in the API headers, and our code
 * is recompiled then it would cease working on old kernels, as those refuse any sizes larger than this value with
 * EINVAL right-away. Hence, let's disconnect ourselves from any such API changes, and stick to the original definition
 * from when it was introduced. We use it as a start value only anyway (see below), and hence should be able to deal
 * with large file handles anyway. */
#define ORIGINAL_MAX_HANDLE_SZ 128

int name_to_handle_at_loop(
                int fd,
                const char *path,
                struct file_handle **ret_handle,
                int *ret_mnt_id,
                int flags) {

        size_t n = ORIGINAL_MAX_HANDLE_SZ;

        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        /* We need to invoke name_to_handle_at() in a loop, given that it might return EOVERFLOW when the specified
         * buffer is too small. Note that in contrast to what the docs might suggest, MAX_HANDLE_SZ is only good as a
         * start value, it is not an upper bound on the buffer size required.
         *
         * This improves on raw name_to_handle_at() also in one other regard: ret_handle and ret_mnt_id can be passed
         * as NULL if there's no interest in either. */

        for (;;) {
                _cleanup_free_ struct file_handle *h = NULL;
                int mnt_id = -1;

                h = malloc0(offsetof(struct file_handle, f_handle) + n);
                if (!h)
                        return -ENOMEM;

                h->handle_bytes = n;

                if (name_to_handle_at(fd, strempty(path), h, &mnt_id, flags) >= 0) {

                        if (ret_handle)
                                *ret_handle = TAKE_PTR(h);

                        if (ret_mnt_id)
                                *ret_mnt_id = mnt_id;

                        return 0;
                }
                if (errno != EOVERFLOW)
                        return -errno;

                if (!ret_handle && ret_mnt_id && mnt_id >= 0) {

                        /* As it appears, name_to_handle_at() fills in mnt_id even when it returns EOVERFLOW when the
                         * buffer is too small, but that's undocumented. Hence, let's make use of this if it appears to
                         * be filled in, and the caller was interested in only the mount ID an nothing else. */

                        *ret_mnt_id = mnt_id;
                        return 0;
                }

                /* If name_to_handle_at() didn't increase the byte size, then this EOVERFLOW is caused by something
                 * else (apparently EOVERFLOW is returned for untriggered nfs4 mounts sometimes), not by the too small
                 * buffer. In that case propagate EOVERFLOW */
                if (h->handle_bytes <= n)
                        return -EOVERFLOW;

                /* The buffer was too small. Size the new buffer by what name_to_handle_at() returned. */
                n = h->handle_bytes;

                /* paranoia: check for overflow (note that .handle_bytes is unsigned only) */
                if (n > UINT_MAX - offsetof(struct file_handle, f_handle))
                        return -EOVERFLOW;
        }
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *ret_mnt_id) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -EBADF;
        char *p;
        int r;

        assert(ret_mnt_id);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_CLOEXEC|O_PATH|(flags & AT_SYMLINK_FOLLOW ? 0 : O_NOFOLLOW));
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_virtual_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return proc_mounted() > 0 ? -EOPNOTSUPP : -ENOSYS;
        if (r < 0)
                return r;

        p = find_line_startswith(fdinfo, "mnt_id:");
        if (!p) /* The mnt_id field is a relatively new addition */
                return -EOPNOTSUPP;

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return safe_atoi(p, ret_mnt_id);
}

static bool is_name_to_handle_at_fatal_error(int err) {
        /* name_to_handle_at() can return "acceptable" errors that are due to the context. For
         * example the kernel does not support name_to_handle_at() at all (ENOSYS), or the syscall
         * was blocked (EACCES/EPERM; maybe through seccomp, because we are running inside of a
         * container), or the mount point is not triggered yet (EOVERFLOW, think nfs4), or some
         * general name_to_handle_at() flakiness (EINVAL). However other errors are not supposed to
         * happen and therefore are considered fatal ones. */

        assert(err < 0);

        return !IN_SET(err, -EOPNOTSUPP, -ENOSYS, -EACCES, -EPERM, -EOVERFLOW, -EINVAL);
}

int path_get_mnt_id_at_fallback(int dir_fd, const char *path, int *ret) {
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        r = name_to_handle_at_loop(dir_fd, path, NULL, ret, isempty(path) ? AT_EMPTY_PATH : 0);
        if (r == 0 || is_name_to_handle_at_fatal_error(r))
                return r;

        return fd_fdinfo_mnt_id(dir_fd, path, isempty(path) ? AT_EMPTY_PATH : 0, ret);
}

bool path_below_api_vfs(const char *p) {
        assert(p);

        /* API VFS are either directly mounted on any of these three paths, or below it. */
        return PATH_STARTSWITH_SET(p, "/dev", "/sys", "/proc");
}
