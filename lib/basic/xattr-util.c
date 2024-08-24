/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#include "svc-config.h"

#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "util.h"
#include "xattr-util.h"

#ifdef HAVE_sys_xattr_h
#include <sys/xattr.h>
#endif

int getxattr_at_malloc(
                int fd,
                const char *path,
                const char *name,
                int flags,
                char **ret) {

        _cleanup_close_ int opened_fd = -EBADF;
        unsigned n_attempts = 7;
        bool by_procfs = false;
        size_t l = 100;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(name);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(ret);

        /* So, this is single function that does what getxattr()/lgetxattr()/fgetxattr() does, but in one go,
         * and with additional bells and whistles. Specifically:
         *
         * 1. This works on O_PATH fds (which fgetxattr() does not)
         * 2. Provides full openat()-style semantics, i.e. by-fd, by-path and combination thereof
         * 3. As extension to openat()-style semantics implies AT_EMPTY_PATH if path is NULL.
         * 4. Does a malloc() loop, automatically sizing the allocation
         * 5. NUL-terminates the returned buffer (for safety)
         */

        if (!path) /* If path is NULL, imply AT_EMPTY_PATH. – But if it's "", don't — for safety reasons. */
                flags |= AT_EMPTY_PATH;

        if (isempty(path)) {
                if (!FLAGS_SET(flags, AT_EMPTY_PATH))
                        return -EINVAL;

                if (fd == AT_FDCWD) /* Both unspecified? Then operate on current working directory */
                        path = ".";
                else
                        path = NULL;

        } else if (fd != AT_FDCWD) {

                /* If both have been specified, then we go via O_PATH */
                opened_fd = openat(fd, path, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
                path = NULL;
                by_procfs = true; /* fgetxattr() is not going to work, go via /proc/ link right-away */
        }

        for (;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                if (n_attempts == 0) /* If someone is racing against us, give up eventually */
                        return -EBUSY;
                n_attempts--;

                v = new0(char, l+1);
                if (!v)
                        return -ENOMEM;

                l = MALLOC_ELEMENTSOF(v) - 1;

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? getxattr(path, name, v, l) : lgetxattr(path, name, v, l);
                else
                        n = by_procfs ? getxattr(FORMAT_PROC_FD_PATH(fd), name, v, l) : fgetxattr(fd, name, v, l);
                if (n < 0) {
                        if (errno == EBADF) {
                                if (by_procfs || path)
                                        return -EBADF;

                                by_procfs = true; /* Might be an O_PATH fd, try again via /proc/ link */
                                continue;
                        }

                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? getxattr(path, name, NULL, 0) : lgetxattr(path, name, NULL, 0);
                else
                        n = by_procfs ? getxattr(FORMAT_PROC_FD_PATH(fd), name, NULL, 0) : fgetxattr(fd, name, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}

int getxattr_at_bool(int fd, const char *path, const char *name, int flags) {
        _cleanup_free_ char *v = NULL;
        int r;

        r = getxattr_at_malloc(fd, path, name, flags, &v);
        if (r < 0)
                return r;

        if (memchr(v, 0, r)) /* Refuse embedded NUL byte */
                return -EINVAL;

        return parse_boolean(v);
}
