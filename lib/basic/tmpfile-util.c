/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "fileio.h"
#include "fs-util.h"
#include "path-util.h"
#include "random-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"

static int fopen_temporary_internal(int dir_fd, const char *path, FILE **ret_file) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        fd = openat(dir_fd, path, O_CLOEXEC|O_NOCTTY|O_RDWR|O_CREAT|O_EXCL, 0600);
        if (fd < 0)
                return -errno;

        /* This assumes that returned FILE object is short-lived and used within the same single-threaded
         * context and never shared externally, hence locking is not necessary. */

        r = take_fdopen_unlocked(&fd, "w", &f);
        if (r < 0) {
                (void) unlinkat(dir_fd, path, 0);
                return r;
        }

        if (ret_file)
                *ret_file = TAKE_PTR(f);

        return 0;
}

int fopen_temporary_at(int dir_fd, const char *path, FILE **ret_file, char **ret_path) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        r = fopen_temporary_internal(dir_fd, t, ret_file);
        if (r < 0)
                return r;

        if (ret_path)
                *ret_path = TAKE_PTR(t);

        return 0;
}

/* This is much like mkostemp() but is subject to umask(). */
int mkostemp_safe(char *pattern) {
        assert(pattern);
        BLOCK_WITH_UMASK(0077);
        return RET_NERRNO(mkostemp(pattern, O_CLOEXEC));
}

int mkdtemp_malloc(const char *template, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(ret);

        if (template)
                p = strdup(template);
        else {
                const char *tmp;

                r = tmp_dir(&tmp);
                if (r < 0)
                        return r;

                p = path_join(tmp, "XXXXXX");
        }
        if (!p)
                return -ENOMEM;

        if (!mkdtemp(p))
                return -errno;

        *ret = TAKE_PTR(p);
        return 0;
}

static int tempfn_build(const char *p, const char *pre, const char *post, bool child, char **ret) {
        _cleanup_free_ char *d = NULL, *fn = NULL, *nf = NULL, *result = NULL;
        size_t len_pre, len_post, len_add;
        int r;

        assert(p);
        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this :
         *         /foo/bar/waldo/.#<pre><post> (child == true)
         *         /foo/bar/.#<pre>waldo<post> (child == false)
         */

        if (pre && strchr(pre, '/'))
                return -EINVAL;

        if (post && strchr(post, '/'))
                return -EINVAL;

        len_pre = strlen_ptr(pre);
        len_post = strlen_ptr(post);
        /* NAME_MAX is counted *without* the trailing NUL byte. */
        if (len_pre > NAME_MAX - STRLEN(".#") ||
            len_post > NAME_MAX - STRLEN(".#") - len_pre)
                return -EINVAL;

        len_add = len_pre + len_post + STRLEN(".#");

        if (child) {
                d = strdup(p);
                if (!d)
                        return -ENOMEM;
        } else {
                r = path_extract_directory(p, &d);
                if (r < 0 && r != -EDESTADDRREQ) /* EDESTADDRREQ → No directory specified, just a filename */
                        return r;

                r = path_extract_filename(p, &fn);
                if (r < 0)
                        return r;

                if (strlen(fn) > NAME_MAX - len_add)
                        /* We cannot simply prepend and append strings to the filename. Let's truncate the filename. */
                        fn[NAME_MAX - len_add] = '\0';
        }

        nf = strjoin(".#", strempty(pre), strempty(fn), strempty(post));
        if (!nf)
                return -ENOMEM;

        if (d) {
                if (!path_extend(&d, nf))
                        return -ENOMEM;

                result = path_simplify(TAKE_PTR(d));
        } else
                result = TAKE_PTR(nf);

        if (!path_is_valid(result)) /* New path is not valid? (Maybe because too long?) Refuse. */
                return -EINVAL;

        *ret = TAKE_PTR(result);
        return 0;
}

int tempfn_xxxxxx(const char *p, const char *extra, char **ret) {
        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#<extra>waldoXXXXXX
         */

        return tempfn_build(p, extra, "XXXXXX", /* child = */ false, ret);
}

int tempfn_random(const char *p, const char *extra, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert(p);
        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#<extra>waldobaa2a261115984a9
         */

        if (asprintf(&s, "%016" PRIx64, random_u64()) < 0)
                return -ENOMEM;

        return tempfn_build(p, extra, s, /* child = */ false, ret);
}
