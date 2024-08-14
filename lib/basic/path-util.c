/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/statvfs.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bsdglibc.h"
#include "chase.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "path-util.h"
#include "stat-util.h"
#include "strv.h"
#include "util.h"

bool
path_is_absolute(const char *p)
{
	return p[0] == '/';
}

bool
is_path(const char *p)
{
	return !!strchr(p, '/');
}

int
path_get_parent(const char *path, char **_r)
{
	const char *e, *a = NULL, *b = NULL, *p;
	char *r;
	bool slash = false;

	assert(path);
	assert(_r);

	if (!*path)
		return -EINVAL;

	for (e = path; *e; e++) {
		if (!slash && *e == '/') {
			a = b;
			b = e;
			slash = true;
		} else if (slash && *e != '/')
			slash = false;
	}

	if (*(e - 1) == '/')
		p = a;
	else
		p = b;

	if (!p)
		return -EINVAL;

	if (p == path)
		r = strdup("/");
	else
		r = strndup(path, p - path);

	if (!r)
		return -ENOMEM;

	*_r = r;
	return 0;
}

int path_split_and_make_absolute(const char *p, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(p);
        assert(ret);

        l = strv_split(p, ":");
        if (!l)
                return -ENOMEM;

        r = path_strv_make_absolute_cwd(l);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(l);
        return r;
}

char *
path_make_absolute(const char *p, const char *prefix)
{
	assert(p);

	/* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

	if (path_is_absolute(p) || !prefix)
		return strdup(p);

	return strjoin(prefix, "/", p, NULL);
}

bool dot_or_dot_dot(const char *path) {
        if (!path)
                return false;
        if (path[0] != '.')
                return false;
        if (path[1] == 0)
                return true;
        if (path[1] != '.')
                return false;

        return path[2] == 0;
}

bool hidden_or_backup_file(const char *filename) {
        assert(filename);

        if (filename[0] == '.' ||
            STR_IN_SET(filename,
                       "lost+found",
                       "aquota.user",
                       "aquota.group") ||
            endswith(filename, "~"))
                return true;

        const char *dot = strrchr(filename, '.');
        if (!dot)
                return false;

        /* Please, let's not add more entries to the list below. If external projects think it's a good idea
         * to come up with always new suffixes and that everybody else should just adjust to that, then it
         * really should be on them. Hence, in future, let's not add any more entries. Instead, let's ask
         * those packages to instead adopt one of the generic suffixes/prefixes for hidden files or backups,
         * possibly augmented with an additional string. Specifically: there's now:
         *
         *    The generic suffixes "~" and ".bak" for backup files
         *    The generic prefix "." for hidden files
         *
         * Thus, if a new package manager "foopkg" wants its own set of ".foopkg-new", ".foopkg-old",
         * ".foopkg-dist" or so registered, let's refuse that and ask them to use ".foopkg.new",
         * ".foopkg.old" or ".foopkg~" instead.
         */

        return STR_IN_SET(dot + 1,
                          "rpmnew",
                          "rpmsave",
                          "rpmorig",
                          "dpkg-old",
                          "dpkg-new",
                          "dpkg-tmp",
                          "dpkg-dist",
                          "dpkg-bak",
                          "dpkg-backup",
                          "dpkg-remove",
                          "ucf-new",
                          "ucf-old",
                          "ucf-dist",
                          "swp",
                          "bak",
                          "old",
                          "new");
}

int safe_getcwd(char **ret) {
        _cleanup_free_ char *cwd = NULL;

        cwd = get_current_dir_name();
        if (!cwd)
                return negative_errno();

        /* Let's make sure the directory is really absolute, to protect us from the logic behind
         * CVE-2018-1000001 */
        if (cwd[0] != '/')
                return -ENOMEDIUM;

        if (ret)
                *ret = TAKE_PTR(cwd);

        return 0;
}

int path_make_absolute_cwd(const char *p, char **ret) {
        char *c;
        int r;

        assert(p);
        assert(ret);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                c = strdup(p);
        else {
                _cleanup_free_ char *cwd = NULL;

                r = safe_getcwd(&cwd);
                if (r < 0)
                        return r;

                c = path_join(cwd, p);
        }
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

int
path_make_relative(const char *from_dir, const char *to_path, char **_r)
{
	char *r, *p;
	unsigned n_parents;

	assert(from_dir);
	assert(to_path);
	assert(_r);

	/* Strips the common part, and adds ".." elements as necessary. */

	if (!path_is_absolute(from_dir))
		return -EINVAL;

	if (!path_is_absolute(to_path))
		return -EINVAL;

	/* Skip the common part. */
	for (;;) {
		size_t a;
		size_t b;

		from_dir += strspn(from_dir, "/");
		to_path += strspn(to_path, "/");

		if (!*from_dir) {
			if (!*to_path)
				/* from_dir equals to_path. */
				r = strdup(".");
			else
				/* from_dir is a parent directory of to_path. */
				r = strdup(to_path);

			if (!r)
				return -ENOMEM;

			path_kill_slashes(r);

			*_r = r;
			return 0;
		}

		if (!*to_path)
			break;

		a = strcspn(from_dir, "/");
		b = strcspn(to_path, "/");

		if (a != b)
			break;

		if (memcmp(from_dir, to_path, a) != 0)
			break;

		from_dir += a;
		to_path += b;
	}

	/* If we're here, then "from_dir" has one or more elements that need to
         * be replaced with "..". */

	/* Count the number of necessary ".." elements. */
	for (n_parents = 0;;) {
		from_dir += strspn(from_dir, "/");

		if (!*from_dir)
			break;

		from_dir += strcspn(from_dir, "/");
		n_parents++;
	}

	r = malloc(n_parents * 3 + strlen(to_path) + 1);
	if (!r)
		return -ENOMEM;

	for (p = r; n_parents > 0; n_parents--, p += 3)
		memcpy(p, "../", 3);

	strcpy(p, to_path);
	path_kill_slashes(r);

	*_r = r;
	return 0;
}

int path_strv_make_absolute_cwd(char **l) {
        int r;

        /* Goes through every item in the string list and makes it
         * absolute. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t;

                r = path_make_absolute_cwd(*s, &t);
                if (r < 0)
                        return r;

                path_simplify(t);
                free_and_replace(*s, t);
        }

        return 0;
}

char **
path_strv_resolve(char **l, const char *prefix)
{
	char **s;
	unsigned k = 0;
	bool enomem = false;

	if (strv_isempty(l))
		return l;

	/* Goes through every item in the string list and canonicalize
         * the path. This works in place and won't rollback any
         * changes on failure. */

	STRV_FOREACH (s, l) {
		char *t, *u;
		_cleanup_free_ char *orig = NULL;

		if (!path_is_absolute(*s)) {
			free(*s);
			continue;
		}

		if (prefix) {
			orig = *s;
			t = strappend(prefix, orig);
			if (!t) {
				enomem = true;
				continue;
			}
		} else
			t = *s;

		errno = 0;
		u = canonicalize_file_name(t);
		if (!u) {
			if (errno == ENOENT) {
				if (prefix) {
					u = orig;
					orig = NULL;
					free(t);
				} else
					u = t;
			} else {
				free(t);
				if (errno == ENOMEM || errno == 0)
					enomem = true;

				continue;
			}
		} else if (prefix) {
			char *x;

			free(t);
			x = path_startswith(u, prefix);
			if (x) {
				/* restore the slash if it was lost */
				if (!startswith(x, "/"))
					*(--x) = '/';

				t = strdup(x);
				free(u);
				if (!t) {
					enomem = true;
					continue;
				}
				u = t;
			} else {
				/* canonicalized path goes outside of
                                 * prefix, keep the original path instead */
				free(u);
				u = orig;
				orig = NULL;
			}
		} else
			free(t);

		l[k++] = u;
	}

	l[k] = NULL;

	if (enomem)
		return NULL;

	return l;
}

char **
path_strv_resolve_uniq(char **l, const char *prefix)
{
	if (strv_isempty(l))
		return l;

	if (!path_strv_resolve(l, prefix))
		return NULL;

	return strv_uniq(l);
}

char *
path_kill_slashes(char *path)
{
	char *f, *t;
	bool slash = false;

	/* Removes redundant inner and trailing slashes. Modifies the
         * passed string in-place.
         *
         * ///foo///bar/ becomes /foo/bar
         */

	for (f = path, t = path; *f; f++) {
		if (*f == '/') {
			slash = true;
			continue;
		}

		if (slash) {
			slash = false;
			*(t++) = '/';
		}

		*(t++) = *f;
	}

	/* Special rule, if we are talking of the root directory, a
        trailing slash is good */

	if (t == path && slash)
		*(t++) = '/';

	*t = 0;
	return path;
}

char *
path_startswith(const char *path, const char *prefix)
{
	assert(path);
	assert(prefix);

	if ((path[0] == '/') != (prefix[0] == '/'))
		return NULL;

	for (;;) {
		size_t a, b;

		path += strspn(path, "/");
		prefix += strspn(prefix, "/");

		if (*prefix == 0)
			return (char *)path;

		if (*path == 0)
			return NULL;

		a = strcspn(path, "/");
		b = strcspn(prefix, "/");

		if (a != b)
			return NULL;

		if (memcmp(path, prefix, a) != 0)
			return NULL;

		path += a;
		prefix += b;
	}
}

int
path_compare(const char *a, const char *b)
{
	int d;

	assert(a);
	assert(b);

	/* A relative path and an abolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
	d = (a[0] == '/') - (b[0] == '/');
	if (d)
		return d;

	for (;;) {
		size_t j, k;

		a += strspn(a, "/");
		b += strspn(b, "/");

		if (*a == 0 && *b == 0)
			return 0;

		/* Order prefixes first: "/foo" before "/foo/bar" */
		if (*a == 0)
			return -1;
		if (*b == 0)
			return 1;

		j = strcspn(a, "/");
		k = strcspn(b, "/");

		/* Alphabetical sort: "/foo/aaa" before "/foo/b" */
		d = memcmp(a, b, MIN(j, k));
		if (d)
			return (d > 0) - (d < 0); /* sign of d */

		/* Sort "/foo/a" before "/foo/aaa" */
		d = (j > k) - (j < k); /* sign of (j - k) */
		if (d)
			return d;

		a += j;
		b += k;
	}
}

static const char* skip_slash_or_dot(const char *p) {
        for (; !isempty(p); p++) {
                if (*p == '/')
                        continue;
                if (startswith(p, "./")) {
                        p++;
                        continue;
                }
                break;
        }
        return p;
}

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret) {
        const char *q, *first, *end_first, *next;
        size_t len;

        assert(p);

        /* When a path is input, then returns the pointer to the first component and its length, and
         * move the input pointer to the next component or nul. This skips both over any '/'
         * immediately *before* and *after* the first component before returning.
         *
         * Examples
         *   Input:  p: "//.//aaa///bbbbb/cc"
         *   Output: p: "bbbbb///cc"
         *           ret: "aaa///bbbbb/cc"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "aaa//"
         *   Output: p: (pointer to NUL)
         *           ret: "aaa//"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "/", ".", ""
         *   Output: p: (pointer to NUL)
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: NULL
         *   Output: p: NULL
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: "(too long component)"
         *   Output: return value: -EINVAL
         *
         *   (when accept_dot_dot is false)
         *   Input:  p: "//..//aaa///bbbbb/cc"
         *   Output: return value: -EINVAL
         */

        q = *p;

        first = skip_slash_or_dot(q);
        if (isempty(first)) {
                *p = first;
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (streq(first, ".")) {
                *p = first + 1;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        end_first = strchrnul(first, '/');
        len = end_first - first;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
                return -EINVAL;

        next = skip_slash_or_dot(end_first);

        *p = next + streq(next, ".");
        if (ret)
                *ret = first;
        return len;
}

int path_extract_filename(const char *path, char **ret) {
        _cleanup_free_ char *a = NULL;
        const char *c, *next = NULL;
        int r;

        /* Extracts the filename part (i.e. right-most component) from a path, i.e. string that passes
         * filename_is_valid(). A wrapper around last_path_component(), but eats up trailing
         * slashes. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EADDRNOTAVAIL → if only a directory was specified, but no filename, i.e. the root dir
         *                  itself or "." is specified
         * -ENOMEM        → no memory
         *
         * Returns >= 0 on success. If the input path has a trailing slash, returns O_DIRECTORY, to
         * indicate the referenced file must be a directory.
         *
         * This function guarantees to return a fully valid filename, i.e. one that passes
         * filename_is_valid() – this means "." and ".." are not accepted. */

        if (!path_is_valid(path))
                return -EINVAL;

        r = path_find_last_component(path, false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* root directory */
                return -EADDRNOTAVAIL;

        a = strndup(c, r);
        if (!a)
                return -ENOMEM;

        *ret = TAKE_PTR(a);
        return strlen(c) > (size_t) r ? O_DIRECTORY : 0;
}

int path_extract_directory(const char *path, char **ret) {
        const char *c, *next = NULL;
        int r;

        /* The inverse of path_extract_filename(), i.e. returns the directory path prefix. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EDESTADDRREQ  → if no directory was specified in the passed in path, i.e. only a filename was passed
         * -EADDRNOTAVAIL → if the passed in parameter had no filename but did have a directory, i.e.
         *                   the root dir itself or "." was specified
         * -ENOMEM        → no memory (surprise!)
         *
         * This function guarantees to return a fully valid path, i.e. one that passes path_is_valid().
         */

        r = path_find_last_component(path, false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* empty or root */
                return isempty(path) ? -EINVAL : -EADDRNOTAVAIL;
        if (next == path) {
                if (*path != '/') /* filename only */
                        return -EDESTADDRREQ;

                return strdup_to(ret, "/");
        }

        _cleanup_free_ char *a = strndup(path, next - path);
        if (!a)
                return -ENOMEM;

        path_simplify(a);

        if (!path_is_valid(a))
                return -EINVAL;

        if (ret)
                *ret = TAKE_PTR(a);

        return 0;
}

bool filename_part_is_valid(const char *p) {
        const char *e;

        /* Checks f the specified string is OK to be *part* of a filename. This is different from
         * filename_is_valid() as "." and ".." and "" are OK by this call, but not by filename_is_valid(). */

        if (!p)
                return false;

        e = strchrnul(p, '/');
        if (*e != 0)
                return false;

        if (e - p > NAME_MAX) /* NAME_MAX is counted *without* the trailing NUL byte */
                return false;

        return true;
}

bool filename_is_valid(const char *p) {

        if (isempty(p))
                return false;

        if (dot_or_dot_dot(p)) /* Yes, in this context we consider "." and ".." invalid */
                return false;

        return filename_part_is_valid(p);
}

bool path_is_valid_full(const char *p, bool accept_dot_dot) {
        if (isempty(p))
                return false;

        for (const char *e = p;;) {
                int r;

                r = path_find_first_component(&e, accept_dot_dot, NULL);
                if (r < 0)
                        return false;

                if (e - p >= PATH_MAX) /* Already reached the maximum length for a path? (PATH_MAX is counted
                                        * *with* the trailing NUL byte) */
                        return false;
                if (*e == 0)           /* End of string? Yay! */
                        return true;
        }
}

int path_compare_filename(const char *a, const char *b) {
        _cleanup_free_ char *fa = NULL, *fb = NULL;
        int r, j, k;

        /* Order NULL before non-NULL */
        r = CMP(!!a, !!b);
        if (r != 0)
                return r;

        j = path_extract_filename(a, &fa);
        k = path_extract_filename(b, &fb);

        /* When one of paths is "." or root, then order it earlier. */
        r = CMP(j != -EADDRNOTAVAIL, k != -EADDRNOTAVAIL);
        if (r != 0)
                return r;

        /* When one of paths is invalid (or we get OOM), order invalid path after valid one. */
        r = CMP(j < 0, k < 0);
        if (r != 0)
                return r;

        /* fallback to use strcmp() if both paths are invalid. */
        if (j < 0)
                return strcmp(a, b);

        return strcmp(fa, fb);
}

int path_equal_or_inode_same_full(const char *a, const char *b, int flags) {
        /* Returns true if paths are of the same entry, false if not, <0 on error. */

        if (path_equal(a, b))
                return 1;

        if (!a || !b)
                return 0;

        return inode_same(a, b, flags);
}

char* path_extend_internal(char **x, ...) {
        size_t sz, old_sz;
        char *q, *nx;
        const char *p;
        va_list ap;
        bool slash;

        /* Joins all listed strings until the sentinel and places a "/" between them unless the strings
         * end/begin already with one so that it is unnecessary. Note that slashes which are already
         * duplicate won't be removed. The string returned is hence always equal to or longer than the sum of
         * the lengths of the individual strings.
         *
         * The first argument may be an already allocated string that is extended via realloc() if
         * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
         * first parameter to distinguish the two operations.
         *
         * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of
         * which some are optional.
         *
         * Examples:
         *
         * path_join("foo", "bar") → "foo/bar"
         * path_join("foo/", "bar") → "foo/bar"
         * path_join("", "foo", "", "bar", "") → "foo/bar" */

        sz = old_sz = x ? strlen_ptr(*x) : 0;
        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                size_t add;

                if (isempty(p))
                        continue;

                add = 1 + strlen(p);
                if (sz > SIZE_MAX - add) { /* overflow check */
                        va_end(ap);
                        return NULL;
                }

                sz += add;
        }
        va_end(ap);

        nx = realloc(x ? *x : NULL, GREEDY_ALLOC_ROUND_UP(sz+1));
        if (!nx)
                return NULL;
        if (x)
                *x = nx;

        if (old_sz > 0)
                slash = nx[old_sz-1] == '/';
        else {
                nx[old_sz] = 0;
                slash = true; /* no need to generate a slash anymore */
        }

        q = nx + old_sz;

        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                if (isempty(p))
                        continue;

                if (!slash && p[0] != '/')
                        *(q++) = '/';

                q = stpcpy(q, p);
                slash = endswith(p, "/");
        }
        va_end(ap);

        return nx;
}

static int
fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *mnt_id)
{
#ifdef SVC_PLATFORM_Linux
	char path[strlen("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
	_cleanup_free_ char *fdinfo = NULL;
	_cleanup_close_ int subfd = -1;
	char *p;
	int r;

	if ((flags & AT_EMPTY_PATH) && isempty(filename))
		xsprintf(path, "/proc/self/fdinfo/%i", fd);
	else {
		subfd = openat(fd, filename,
			O_CLOEXEC | O_PATH |
				(flags & AT_SYMLINK_FOLLOW ? 0 : O_NOFOLLOW));
		if (subfd < 0)
			return -errno;

		xsprintf(path, "/proc/self/fdinfo/%i", subfd);
	}

	r = read_full_file(path, &fdinfo, NULL);
	if (r ==
		-ENOENT) /* The fdinfo directory is a relatively new addition */
		return -EOPNOTSUPP;
	if (r < 0)
		return -errno;

	p = startswith(fdinfo, "mnt_id:");
	if (!p) {
		p = strstr(fdinfo, "\nmnt_id:");
		if (!p) /* The mnt_id field is a relatively new addition */
			return -EOPNOTSUPP;

		p += 8;
	}

	p += strspn(p, WHITESPACE);
	p[strcspn(p, WHITESPACE)] = 0;

	return safe_atoi(p, mnt_id);
#else
	return 0;
#endif
}

int
fd_is_mount_point(int fd, const char *filename, int flags)
{
#ifdef SVC_PLATFORM_Linux
	union file_handle_union h = FILE_HANDLE_INIT,
				h_parent = FILE_HANDLE_INIT;
	int mount_id = -1, mount_id_parent = -1;
	bool nosupp = false, check_st_dev = true;
	struct stat a, b;
	int r;

	assert(fd >= 0);
	assert(filename);

	/* First we will try the name_to_handle_at() syscall, which
         * tells us the mount id and an opaque file "handle". It is
         * not supported everywhere though (kernel compile-time
         * option, not all file systems are hooked up). If it works
         * the mount id is usually good enough to tell us whether
         * something is a mount point.
         *
         * If that didn't work we will try to read the mount id from
         * /proc/self/fdinfo/<fd>. This is almost as good as
         * name_to_handle_at(), however, does not return the
         * opaque file handle. The opaque file handle is pretty useful
         * to detect the root directory, which we should always
         * consider a mount point. Hence we use this only as
         * fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev
         * comparisons. This is how things were traditionally done,
         * but unionfs breaks this since it exposes file
         * systems with a variety of st_dev reported. Also, btrfs
         * subvolumes have different st_dev, even though they aren't
         * real mounts of their own. */

	r = name_to_handle_at(fd, filename, &h.handle, &mount_id, flags);
	if (r < 0) {
		if (IN_SET(errno, ENOSYS, EACCES, EPERM))
			/* This kernel does not support name_to_handle_at() at all, or the syscall was blocked (maybe
                         * through seccomp, because we are running inside of a container?): fall back to simpler
                         * logic. */
			goto fallback_fdinfo;
		else if (errno == EOPNOTSUPP)
			/* This kernel or file system does not support
                         * name_to_handle_at(), hence let's see if the
                         * upper fs supports it (in which case it is a
                         * mount point), otherwise fallback to the
                         * traditional stat() logic */
			nosupp = true;
		else
			return -errno;
	}

	r = name_to_handle_at(fd, "", &h_parent.handle, &mount_id_parent,
		AT_EMPTY_PATH);
	if (r < 0) {
		if (errno == EOPNOTSUPP) {
			if (nosupp)
				/* Neither parent nor child do name_to_handle_at()?
                                   We have no choice but to fall back. */
				goto fallback_fdinfo;
			else
				/* The parent can't do name_to_handle_at() but the
                                 * directory we are interested in can?
                                 * If so, it must be a mount point. */
				return 1;
		} else
			return -errno;
	}

	/* The parent can do name_to_handle_at() but the
         * directory we are interested in can't? If so, it
         * must be a mount point. */
	if (nosupp)
		return 1;

	/* If the file handle for the directory we are
         * interested in and its parent are identical, we
         * assume this is the root directory, which is a mount
         * point. */

	if (h.handle.handle_bytes == h_parent.handle.handle_bytes &&
		h.handle.handle_type == h_parent.handle.handle_type &&
		memcmp(h.handle.f_handle, h_parent.handle.f_handle,
			h.handle.handle_bytes) == 0)
		return 1;

	return mount_id != mount_id_parent;

fallback_fdinfo:
	r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
	if (IN_SET(r, -EOPNOTSUPP, -EACCES, -EPERM))
		goto fallback_fstat;
	if (r < 0)
		return r;

	r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id_parent);
	if (r < 0)
		return r;

	if (mount_id != mount_id_parent)
		return 1;

	/* Hmm, so, the mount ids are the same. This leaves one
         * special case though for the root file system. For that,
         * let's see if the parent directory has the same inode as we
         * are interested in. Hence, let's also do fstat() checks now,
         * too, but avoid the st_dev comparisons, since they aren't
         * that useful on unionfs mounts. */
	check_st_dev = false;

fallback_fstat:
	/* yay for fstatat() taking a different set of flags than the other
         * _at() above */
	if (flags & AT_SYMLINK_FOLLOW)
		flags &= ~AT_SYMLINK_FOLLOW;
	else
		flags |= AT_SYMLINK_NOFOLLOW;
	if (fstatat(fd, filename, &a, flags) < 0)
		return -errno;

	if (fstatat(fd, "", &b, AT_EMPTY_PATH) < 0)
		return -errno;

	/* A directory with same device and inode as its parent? Must
         * be the root directory */
	if (a.st_dev == b.st_dev && a.st_ino == b.st_ino)
		return 1;

	return check_st_dev && (a.st_dev != b.st_dev);
#else
	unimplemented();
	return true;
#endif
}

int
path_is_mount_point(const char *t, bool allow_symlink)
{
#ifdef SVC_PLATFORM_Linux
	_cleanup_free_ char *canonical = NULL, *parent = NULL;
	_cleanup_close_ int fd = -1;
	int flags = allow_symlink ? AT_SYMLINK_FOLLOW : 0;

	assert(t);

	if (path_equal(t, "/"))
		return 1;

	/* we need to resolve symlinks manually, we can't just rely on
         * fd_is_mount_point() to do that for us; if we have a structure like
         * /bin -> /usr/bin/ and /usr is a mount point, then the parent that we
         * look at needs to be /usr, not /. */
	if (flags & AT_SYMLINK_FOLLOW) {
		canonical = canonicalize_file_name(t);
		if (!canonical) {
			if (errno == ENOENT)
				return 0;
			else
				return -errno;
		}
		t = canonical;
	}

	parent = dirname_malloc(t);
	if (!parent)
		return -ENOMEM;

	fd = openat(AT_FDCWD, parent, O_DIRECTORY | O_CLOEXEC | O_PATH);
	if (fd < 0)
		return -errno;

	return fd_is_mount_point(fd, lsb_basename(t), flags);
#else
	unimplemented();
	return true;
#endif
}

int
path_is_read_only_fs(const char *path)
{
	struct statvfs st;

	assert(path);

	if (statvfs(path, &st) < 0)
		return -errno;

	if (st.f_flag & ST_RDONLY)
		return true;

	/* On NFS, statvfs() might not reflect whether we can actually
         * write to the remote share. Let's try again with
         * access(W_OK) which is more reliable, at least sometimes. */
	if (access(path, W_OK) < 0 && errno == EROFS)
		return true;

	return false;
}

int
path_is_os_tree(const char *path)
{
	char *p;
	int r;

	/* We use /usr/lib/os-release as flag file if something is an OS */
	p = strjoina(path, "/usr/lib/os-release");
	r = access(p, F_OK);

	if (r >= 0)
		return 1;

	/* Also check for the old location in /etc, just in case. */
	p = strjoina(path, "/etc/os-release");
	r = access(p, F_OK);

	return r >= 0;
}

static int check_x_access(const char *path, int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* We need to use O_PATH because there may be executables for which we have only exec
         * permissions, but not read (usually suid executables). */
        fd = open(path, O_PATH|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        r = access_fd(fd, X_OK);
        if (r == -ENOSYS) {
                /* /proc is not mounted. Fallback to access(). */
                if (access(path, X_OK) < 0)
                        return -errno;
        } else if (r < 0)
                return r;

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

static int find_executable_impl(const char *name, const char *root, char **ret_filename, int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path_name = NULL;
        int r;

        assert(name);

        /* Function chase() is invoked only when root is not NULL, as using it regardless of
         * root value would alter the behavior of existing callers for example: /bin/sleep would become
         * /usr/bin/sleep when find_executables is called. Hence, this function should be invoked when
         * needed to avoid unforeseen regression or other complicated changes. */
        if (root) {
                 /* prefix root to name in case full paths are not specified */
                r = chase(name, root, CHASE_PREFIX_ROOT, &path_name, /* ret_fd= */ NULL);
                if (r < 0)
                        return r;

                name = path_name;
        }

        r = check_x_access(name, ret_fd ? &fd : NULL);
        if (r < 0)
                return r;

        if (ret_filename) {
                r = path_make_absolute_cwd(name, ret_filename);
                if (r < 0)
                        return r;
        }

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

int find_executable_full(
                const char *name,
                const char *root,
                char **exec_search_path,
                bool use_path_envvar,
                char **ret_filename,
                int *ret_fd) {

        int last_error = -ENOENT, r = 0;
        const char *p = NULL;

        assert(name);

        if (is_path(name))
                return find_executable_impl(name, root, ret_filename, ret_fd);

        if (use_path_envvar)
                /* Plain getenv, not secure_getenv, because we want to actually allow the user to pick the
                 * binary. */
                p = getenv("PATH");
        if (!p)
                p = default_PATH();

        if (exec_search_path) {
                STRV_FOREACH(element, exec_search_path) {
                        _cleanup_free_ char *full_path = NULL;

                        if (!path_is_absolute(*element))
                                continue;

                        full_path = path_join(*element, name);
                        if (!full_path)
                                return -ENOMEM;

                        r = find_executable_impl(full_path, root, ret_filename, ret_fd);
                        if (r < 0) {
                                if (r != -EACCES)
                                        last_error = r;
                                continue;
                        }
                        return 0;
                }
                return last_error;
        }

        /* Resolve a single-component name to a full path */
        for (;;) {
                _cleanup_free_ char *element = NULL;

                r = extract_first_word(&p, &element, ":", EXTRACT_RELAX|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!path_is_absolute(element))
                        continue;

                if (!path_extend(&element, name))
                        return -ENOMEM;

                r = find_executable_impl(element, root, ret_filename, ret_fd);
                if (r < 0) {
                        /* PATH entries which we don't have access to are ignored, as per tradition. */
                        if (r != -EACCES)
                                last_error = r;
                        continue;
                }

                /* Found it! */
                return 0;
        }

        return last_error;
}

bool
paths_check_timestamp(const char *const *paths, usec_t *timestamp, bool update)
{
	bool changed = false;
	const char *const *i;

	assert(timestamp);

	if (paths == NULL)
		return false;

	STRV_FOREACH (i, paths) {
		struct stat stats;
		usec_t u;

		if (stat(*i, &stats) < 0)
			continue;

		u = timespec_load(&stats.st_mtim);

		/* first check */
		if (*timestamp >= u)
			continue;

		log_debug("timestamp of '%s' changed", *i);

		/* update timestamp */
		if (update) {
			*timestamp = u;
			changed = true;
		} else
			return true;
	}

	return changed;
}

static int executable_is_good(const char *executable) {
        _cleanup_free_ char *p = NULL, *d = NULL;
        int r;

        r = find_executable(executable, &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        /* An fsck that is linked to /bin/true is a non-existent fsck */

        r = readlink_malloc(p, &d);
        if (r == -EINVAL) /* not a symlink */
                return 1;
        if (r < 0)
                return r;

        return !PATH_IN_SET(d, "true"
                               "/bin/true",
                               "/usr/bin/true",
                               "/dev/null");
}

int fsck_exists(void) {
        return executable_is_good("fsck");
}

int fsck_exists_for_fstype(const char *fstype) {
        const char *checker;
        int r;

        assert(fstype);

        if (streq(fstype, "auto"))
                return -EINVAL;

        r = fsck_exists();
        if (r <= 0)
                return r;

        checker = strjoina("fsck.", fstype);
        return executable_is_good(checker);
}

char *
prefix_root(const char *root, const char *path)
{
	char *n, *p;
	size_t l;

	/* If root is passed, prefixes path with it. Otherwise returns
         * it as is. */

	assert(path);

	/* First, drop duplicate prefixing slashes from the path */
	while (path[0] == '/' && path[1] == '/')
		path++;

	if (isempty(root) || path_equal(root, "/"))
		return strdup(path);

	l = strlen(root) + 1 + strlen(path) + 1;

	n = new (char, l);
	if (!n)
		return NULL;

	p = stpcpy(n, root);

	while (p > n && p[-1] == '/')
		p--;

	if (path[0] != '/')
		*(p++) = '/';

	strcpy(p, path);
	return n;
}

int
inotify_add_watch_fd(int fd, int what, uint32_t mask)
{
	char path[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
	int r;

	/* This is like inotify_add_watch(), except that the file to watch is not referenced by a path, but by an fd */
	xsprintf(path, "/proc/self/fd/%i", what);

	r = inotify_add_watch(fd, path, mask);
	if (r < 0)
		return -errno;

	return r;
}

const char* default_PATH(void) {
#if HAVE_SPLIT_BIN
        static int split = -1;
        int r;

        /* Check whether /usr/sbin is not a symlink and return the appropriate $PATH.
         * On error fall back to the safe value with both directories as configured… */

        if (split < 0)
                STRV_FOREACH_PAIR(bin, sbin, STRV_MAKE("/usr/bin", "/usr/sbin",
                                                       "/usr/local/bin", "/usr/local/sbin")) {
                        r = inode_same(*bin, *sbin, AT_NO_AUTOMOUNT);
                        if (r > 0 || r == -ENOENT)
                                continue;
                        if (r < 0)
                                log_debug_errno(r, "Failed to compare \"%s\" and \"%s\", using compat $PATH: %m",
                                                *bin, *sbin);
                        split = true;
                        break;
                }
        if (split < 0)
                split = false;
        if (split)
                return DEFAULT_PATH_WITH_SBIN;
#endif
        return DEFAULT_PATH_WITHOUT_SBIN;
}
