/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"

#include "svc-config.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/fs.h>
#include <linux/magic.h>
#endif

int fclose_nointr(FILE *f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        errno = 0; /* Extra safety: if the FILE* object is not encapsulating an fd, it might not set errno
                    * correctly. Let's hence initialize it to zero first, so that we aren't confused by any
                    * prior errno here */
        if (fclose(f) == 0)
                return 0;

        if (errno == EINTR)
                return 0;

        return errno_or_else(EIO);
}

FILE* safe_fclose(FILE *f) {

        /* Same as safe_close(), but for fclose() */

        if (f) {
                PROTECT_ERRNO;

                assert_se(fclose_nointr(f) != -EBADF);
        }

        return NULL;
}

int path_is_root_at(int dir_fd, const char *path) {
        _cleanup_close_ int fd = -EBADF, pfd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        if (!isempty(path)) {
                fd = openat(dir_fd, path, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return errno == ENOTDIR ? false : -errno;

                dir_fd = fd;
        }

        pfd = openat(dir_fd, "..", O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (pfd < 0)
                return errno == ENOTDIR ? false : -errno;

        /* Even if the parent directory has the same inode, the fd may not point to the root directory "/",
         * and we also need to check that the mount ids are the same. Otherwise, a construct like the
         * following could be used to trick us:
         *
         * $ mkdir /tmp/x /tmp/x/y
         * $ mount --bind /tmp/x /tmp/x/y
         */

        return fds_are_same_mount(dir_fd, pfd);
}

int fds_are_same_mount(int fd1, int fd2) {
        STRUCT_NEW_STATX_DEFINE(st1);
        STRUCT_NEW_STATX_DEFINE(st2);
        int r;

        assert(fd1 >= 0);
        assert(fd2 >= 0);

        r = statx_fallback(fd1, "", AT_EMPTY_PATH, STATX_TYPE|STATX_INO|STATX_MNT_ID, &st1.sx);
        if (r < 0)
                return r;

        r = statx_fallback(fd2, "", AT_EMPTY_PATH, STATX_TYPE|STATX_INO|STATX_MNT_ID, &st2.sx);
        if (r < 0)
                return r;

        /* First, compare inode. If these are different, the fd does not point to the root directory "/". */
        if (!statx_inode_same(&st1.sx, &st2.sx))
                return false;

        /* Note, statx() does not provide the mount ID and path_get_mnt_id_at() does not work when an old
         * kernel is used. In that case, let's assume that we do not have such spurious mount points in an
         * early boot stage, and silently skip the following check. */

        if (!FLAGS_SET(st1.nsx.stx_mask, STATX_MNT_ID)) {
                int mntid;

                r = path_get_mnt_id_at_fallback(fd1, "", &mntid);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return true; /* skip the mount ID check */
                if (r < 0)
                        return r;
                assert(mntid >= 0);

                st1.nsx.stx_mnt_id = mntid;
                st1.nsx.stx_mask |= STATX_MNT_ID;
        }

        if (!FLAGS_SET(st2.nsx.stx_mask, STATX_MNT_ID)) {
                int mntid;

                r = path_get_mnt_id_at_fallback(fd2, "", &mntid);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return true; /* skip the mount ID check */
                if (r < 0)
                        return r;
                assert(mntid >= 0);

                st2.nsx.stx_mnt_id = mntid;
                st2.nsx.stx_mask |= STATX_MNT_ID;
        }

        return statx_mount_same(&st1.nsx, &st2.nsx);
}

int fd_get_path(int fd, char **ret) {
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);

        if (fd == AT_FDCWD)
                return safe_getcwd(ret);

        r = readlink_malloc(FORMAT_PROC_FD_PATH(fd), ret);
        if (r == -ENOENT) {
                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
                 * things debuggable and distinguish the two. */

                if (proc_mounted() == 0)
                        return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
                                          * environment. */
                return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
        }

        return r;
}

int fd_reopen(int fd, int flags) {
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(!FLAGS_SET(flags, O_CREAT));

        /* Reopens the specified fd with new flags. This is useful for convert an O_PATH fd into a regular one, or to
         * turn O_RDWR fds into O_RDONLY fds.
         *
         * This doesn't work on sockets (since they cannot be open()ed, ever).
         *
         * This implicitly resets the file read index to 0.
         *
         * If AT_FDCWD is specified as file descriptor gets an fd to the current cwd.
         *
         * If the specified file descriptor refers to a symlink via O_PATH, then this function cannot be used
         * to follow that symlink. Because we cannot have non-O_PATH fds to symlinks reopening it without
         * O_PATH will always result in -ELOOP. Or in other words: if you have an O_PATH fd to a symlink you
         * can reopen it only if you pass O_PATH again. */

        if (FLAGS_SET(flags, O_NOFOLLOW))
                /* O_NOFOLLOW is not allowed in fd_reopen(), because after all this is primarily implemented
                 * via a symlink-based interface in /proc/self/fd. Let's refuse this here early. Note that
                 * the kernel would generate ELOOP here too, hence this manual check is mostly redundant –
                 * the only reason we add it here is so that the O_DIRECTORY special case (see below) behaves
                 * the same way as the non-O_DIRECTORY case. */
                return -ELOOP;

        if (FLAGS_SET(flags, O_DIRECTORY) || fd == AT_FDCWD)
                /* If we shall reopen the fd as directory we can just go via "." and thus bypass the whole
                 * magic /proc/ directory, and make ourselves independent of that being mounted. */
                return RET_NERRNO(openat(fd, ".", flags | O_DIRECTORY));

        int new_fd = open(FORMAT_PROC_FD_PATH(fd), flags);
        if (new_fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                r = proc_mounted();
                if (r == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return r > 0 ? -EBADF : -ENOENT; /* If /proc/ is definitely around then this means the fd is
                                                  * not valid, otherwise let's propagate the original
                                                  * error */
        }

        return new_fd;
}

int fd_move_above_stdio(int fd) {
        int flags, copy;
        PROTECT_ERRNO;

        /* Moves the specified file descriptor if possible out of the range [0…2], i.e. the range of
         * stdin/stdout/stderr. If it can't be moved outside of this range the original file descriptor is
         * returned. This call is supposed to be used for long-lasting file descriptors we allocate in our code that
         * might get loaded into foreign code, and where we want ensure our fds are unlikely used accidentally as
         * stdin/stdout/stderr of unrelated code.
         *
         * Note that this doesn't fix any real bugs, it just makes it less likely that our code will be affected by
         * buggy code from others that mindlessly invokes 'fprintf(stderr, …' or similar in places where stderr has
         * been closed before.
         *
         * This function is written in a "best-effort" and "least-impact" style. This means whenever we encounter an
         * error we simply return the original file descriptor, and we do not touch errno. */

        if (fd < 0 || fd > 2)
                return fd;

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return fd;

        if (flags & FD_CLOEXEC)
                copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        else
                copy = fcntl(fd, F_DUPFD, 3);
        if (copy < 0)
                return fd;

        assert(copy > 2);

        (void) close(fd);
        return copy;
}
