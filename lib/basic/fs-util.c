/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include "svc-config.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/falloc.h>
#include <linux/magic.h>
#endif

#include "fd-util.h"
#include "fs-util.h"
#include "label.h"
#include "path-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

static int getenv_tmp_dir(const char **ret_path) {
        int r, ret = 0;

        assert(ret_path);

        /* We use the same order of environment variables python uses in tempfile.gettempdir():
         * https://docs.python.org/3/library/tempfile.html#tempfile.gettempdir */
        FOREACH_STRING(n, "TMPDIR", "TEMP", "TMP") {
                const char *e;

                e = secure_getenv(n);
                if (!e)
                        continue;
                if (!path_is_absolute(e)) {
                        r = -ENOTDIR;
                        goto next;
                }
                if (!path_is_normalized(e)) {
                        r = -EPERM;
                        goto next;
                }

                r = is_dir(e, true);
                if (r < 0)
                        goto next;
                if (r == 0) {
                        r = -ENOTDIR;
                        goto next;
                }

                *ret_path = e;
                return 1;

        next:
                /* Remember first error, to make this more debuggable */
                if (ret >= 0)
                        ret = r;
        }

        if (ret < 0)
                return ret;

        *ret_path = NULL;
        return ret;
}

static int tmp_dir_internal(const char *def, const char **ret) {
        const char *e;
        int r, k;

        assert(def);
        assert(ret);

        r = getenv_tmp_dir(&e);
        if (r > 0) {
                *ret = e;
                return 0;
        }

        k = is_dir(def, true);
        if (k == 0)
                k = -ENOTDIR;
        if (k < 0)
                return r < 0 ? r : k;

        *ret = def;
        return 0;
}

int var_tmp_dir(const char **ret) {

        /* Returns the location for "larger" temporary files, that is backed by physical storage if available, and thus
         * even might survive a boot: /var/tmp. If $TMPDIR (or related environment variables) are set, its value is
         * returned preferably however. Note that both this function and tmp_dir() below are affected by $TMPDIR,
         * making it a variable that overrides all temporary file storage locations. */

        return tmp_dir_internal("/var/tmp", ret);
}

int tmp_dir(const char **ret) {

        /* Similar to var_tmp_dir() above, but returns the location for "smaller" temporary files, which is usually
         * backed by an in-memory file system: /tmp. */

        return tmp_dir_internal("/tmp", ret);
}

int access_fd(int fd, int mode) {
        /* Like access() but operates on an already open fd */

        if (access(FORMAT_PROC_FD_PATH(fd), mode) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's
                 * make things debuggable and distinguish the two. */

                if (proc_mounted() == 0)
                        return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
                                          * environment. */

                return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
        }

        return 0;
}

int stat_warn_permissions(const char *path, const struct stat *st) {
        assert(path);
        assert(st);

        /* Don't complain if we are reading something that is not a file, for example /dev/null */
        if (!S_ISREG(st->st_mode))
                return 0;

        if (st->st_mode & 0111)
                log_warning("Configuration file %s is marked executable. Please remove executable permission bits. Proceeding anyway.", path);

        if (st->st_mode & 0002)
                log_warning("Configuration file %s is marked world-writable. Please remove world writability permission bits. Proceeding anyway.", path);

        if (getpid_cached() == 1 && (st->st_mode & 0044) != 0044)
                log_warning("Configuration file %s is marked world-inaccessible. This has no effect as configuration data is accessible via APIs without restrictions. Proceeding anyway.", path);

        return 0;
}

int xopenat_full(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode) {
        _cleanup_close_ int fd = -EBADF;
        bool made = false;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        /* This is like openat(), but has a few tricks up its sleeves, extending behaviour:
         *
         *   • O_DIRECTORY|O_CREAT is supported, which causes a directory to be created, and immediately
         *     opened. When used with the XO_SUBVOLUME flag this will even create a btrfs subvolume.
         *
         *   • If O_CREAT is used with XO_LABEL, any created file will be immediately relabelled.
         *
         *   • If the path is specified NULL or empty, behaves like fd_reopen().
         */

        if (isempty(path)) {
                assert(!FLAGS_SET(open_flags, O_CREAT|O_EXCL));
                return fd_reopen(dir_fd, open_flags & ~O_NOFOLLOW);
        }

        if (FLAGS_SET(open_flags, O_CREAT) && FLAGS_SET(xopen_flags, XO_LABEL)) {
                r = label_ops_pre(dir_fd, path, FLAGS_SET(open_flags, O_DIRECTORY) ? S_IFDIR : S_IFREG);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(open_flags, O_DIRECTORY|O_CREAT)) {
// HACK!
#if 0
                if (FLAGS_SET(xopen_flags, XO_SUBVOLUME))
                        r = btrfs_subvol_make_fallback(dir_fd, path, mode);
                else
#endif
                r = RET_NERRNO(mkdirat(dir_fd, path, mode));
                if (r == -EEXIST) {
                        if (FLAGS_SET(open_flags, O_EXCL))
                                return -EEXIST;

                        made = false;
                } else if (r < 0)
                        return r;
                else
                        made = true;

                if (FLAGS_SET(xopen_flags, XO_LABEL)) {
                        r = label_ops_post(dir_fd, path);
                        if (r < 0)
                                return r;
                }

                open_flags &= ~(O_EXCL|O_CREAT);
                xopen_flags &= ~XO_LABEL;
        }

        fd = RET_NERRNO(openat(dir_fd, path, open_flags, mode));
        if (fd < 0) {
                if (IN_SET(fd,
                           /* We got ENOENT? then someone else immediately removed it after we
                           * created it. In that case let's return immediately without unlinking
                           * anything, because there simply isn't anything to unlink anymore. */
                           -ENOENT,
                           /* is a symlink? exists already → created by someone else, don't unlink */
                           -ELOOP,
                           /* not a directory? exists already → created by someone else, don't unlink */
                           -ENOTDIR))
                        return fd;

                if (made)
                        (void) unlinkat(dir_fd, path, AT_REMOVEDIR);

                return fd;
        }

        if (FLAGS_SET(open_flags, O_CREAT) && FLAGS_SET(xopen_flags, XO_LABEL)) {
                r = label_ops_post(dir_fd, path);
                if (r < 0)
                        return r;
        }

        return TAKE_FD(fd);
}
