/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdio_ext.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ctype.h"
#include "def.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "utf8.h"
#include "util.h"

/* The maximum size of virtual files (i.e. procfs, sysfs, and other virtual "API" files) we'll read in one go
 * in read_virtual_file(). Note that this limit is different (and much lower) than the READ_FULL_BYTES_MAX
 * limit. This reflects the fact that we use different strategies for reading virtual and regular files:
 * virtual files we generally have to read in a single read() syscall since the kernel doesn't support
 * continuation read()s for them. Thankfully they are somewhat size constrained. Thus we can allocate the
 * full potential buffer in advance. Regular files OTOH can be much larger, and there we grow the allocations
 * exponentially in a loop. We use a size limit of 4M-2 because 4M-1 is the maximum buffer that /proc/sys/
 * allows us to read() (larger reads will fail with ENOMEM), and we want to read one extra byte so that we
 * can detect EOFs. */
#define READ_VIRTUAL_BYTES_MAX (4U * U64_MB - UINT64_C(2))

int
write_string_stream(FILE *f, const char *line)
{
	assert(f);
	assert(line);

	errno = 0;

	fputs(line, f);
	if (!endswith(line, "\n"))
		fputc('\n', f);

	fflush(f);

	if (ferror(f))
		return errno ? -errno : -EIO;

	return 0;
}

int
write_string_file(const char *fn, const char *line)
{
	_cleanup_fclose_ FILE *f = NULL;

	assert(fn);
	assert(line);

	f = fopen(fn, "we");
	if (!f)
		return -errno;

	return write_string_stream(f, line);
}

int
write_string_file_no_create(const char *fn, const char *line)
{
	_cleanup_fclose_ FILE *f = NULL;
	int fd;

	assert(fn);
	assert(line);

	/* We manually build our own version of fopen(..., "we") that
         * works without O_CREAT */
	fd = open(fn, O_WRONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0)
		return -errno;

	f = fdopen(fd, "we");
	if (!f) {
		safe_close(fd);
		return -errno;
	}

	return write_string_stream(f, line);
}

int
write_string_file_atomic(const char *fn, const char *line)
{
	_cleanup_fclose_ FILE *f = NULL;
	_cleanup_free_ char *p = NULL;
	int r;

	assert(fn);
	assert(line);

	r = fopen_temporary(fn, &f, &p);
	if (r < 0)
		return r;

	fchmod_umask(fileno(f), 0644);

	r = write_string_stream(f, line);
	if (r >= 0) {
		if (rename(p, fn) < 0)
			r = -errno;
	}

	if (r < 0)
		unlink(p);

	return r;
}

int
read_one_line_file(const char *fn, char **line)
{
	_cleanup_fclose_ FILE *f = NULL;
	int r;

	assert(fn);
	assert(line);

	f = fopen(fn, "re");
	if (!f)
		return -errno;

	r = read_line(f, LONG_LINE_MAX, line);
	return r < 0 ? r : 0;
}

int read_stripped_line(FILE *f, size_t limit, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r, k;

        assert(f);

        r = read_line(f, limit, ret ? &s : NULL);
        if (r < 0)
                return r;

        if (ret) {
                const char *p = strstrip(s);
                if (p == s)
                        *ret = TAKE_PTR(s);
                else {
                        k = strdup_to(ret, p);
                        if (k < 0)
                                return k;
                }
        }

        return r > 0;          /* Return 1 if something was read. */
}

int fopen_mode_to_flags(const char *mode) {
        const char *p;
        int flags;

        assert(mode);

        if ((p = startswith(mode, "r+")))
                flags = O_RDWR;
        else if ((p = startswith(mode, "r")))
                flags = O_RDONLY;
        else if ((p = startswith(mode, "w+")))
                flags = O_RDWR|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "w")))
                flags = O_WRONLY|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "a+")))
                flags = O_RDWR|O_CREAT|O_APPEND;
        else if ((p = startswith(mode, "a")))
                flags = O_WRONLY|O_CREAT|O_APPEND;
        else
                return -EINVAL;

        for (; *p != 0; p++) {

                switch (*p) {

                case 'e':
                        flags |= O_CLOEXEC;
                        break;

                case 'x':
                        flags |= O_EXCL;
                        break;

                case 'm':
                        /* ignore this here, fdopen() might care later though */
                        break;

                case 'c': /* not sure what to do about this one */
                default:
                        return -EINVAL;
                }
        }

        return flags;
}

int fdopen_independent(int fd, const char *mode, FILE **ret) {
        _cleanup_close_ int copy_fd = -EBADF;
        _cleanup_fclose_ FILE *f = NULL;
        int mode_flags;

        assert(fd >= 0);
        assert(mode);
        assert(ret);

        /* A combination of fdopen() + fd_reopen(). i.e. reopens the inode the specified fd points to and
         * returns a FILE* for it */

        mode_flags = fopen_mode_to_flags(mode);
        if (mode_flags < 0)
                return mode_flags;

        /* Flags returned by fopen_mode_to_flags might contain O_CREAT, but it doesn't make sense for fd_reopen
         * since we're working on an existing fd anyway. Let's drop it here to avoid triggering assertion. */
        copy_fd = fd_reopen(fd, mode_flags & ~O_CREAT);
        if (copy_fd < 0)
                return copy_fd;

        f = take_fdopen(&copy_fd, mode);
        if (!f)
                return -errno;

        *ret = TAKE_PTR(f);
        return 0;
}

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size) {
        _cleanup_free_ char *buf = NULL;
        size_t n, size;
        int n_retries;
        bool truncated = false;

        /* Virtual filesystems such as sysfs or procfs use kernfs, and kernfs can work with two sorts of
         * virtual files. One sort uses "seq_file", and the results of the first read are buffered for the
         * second read. The other sort uses "raw" reads which always go direct to the device. In the latter
         * case, the content of the virtual file must be retrieved with a single read otherwise a second read
         * might get the new value instead of finding EOF immediately. That's the reason why the usage of
         * fread(3) is prohibited in this case as it always performs a second call to read(2) looking for
         * EOF. See issue #13585.
         *
         * max_size specifies a limit on the bytes read. If max_size is SIZE_MAX, the full file is read. If
         * the full file is too large to read, an error is returned. For other values of max_size, *partial
         * contents* may be returned. (Though the read is still done using one syscall.) Returns 0 on
         * partial success, 1 if untruncated contents were read. */

        assert(fd >= 0);
        assert(max_size <= READ_VIRTUAL_BYTES_MAX || max_size == SIZE_MAX);

        /* Limit the number of attempts to read the number of bytes returned by fstat(). */
        n_retries = 3;

        for (;;) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -EBADF;

                /* Be prepared for files from /proc which generally report a file size of 0. */
                assert_cc(READ_VIRTUAL_BYTES_MAX < SSIZE_MAX);
                if (st.st_size > 0 && n_retries > 1) {
                        /* Let's use the file size if we have more than 1 attempt left. On the last attempt
                         * we'll ignore the file size */

                        if (st.st_size > SSIZE_MAX) { /* Avoid overflow with 32-bit size_t and 64-bit off_t. */

                                if (max_size == SIZE_MAX)
                                        return -EFBIG;

                                size = max_size;
                        } else {
                                size = MIN((size_t) st.st_size, max_size);

                                if (size > READ_VIRTUAL_BYTES_MAX)
                                        return -EFBIG;
                        }

                        n_retries--;
                } else if (n_retries > 1) {
                        /* Files in /proc are generally smaller than the page size so let's start with
                         * a page size buffer from malloc and only use the max buffer on the final try. */
                        size = MIN3(page_size() - 1, READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 1;
                } else {
                        size = MIN(READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 0;
                }

                buf = malloc(size + 1);
                if (!buf)
                        return -ENOMEM;

                /* Use a bigger allocation if we got it anyway, but not more than the limit. */
                size = MIN3(MALLOC_SIZEOF_SAFE(buf) - 1, max_size, READ_VIRTUAL_BYTES_MAX);

                for (;;) {
                        ssize_t k;

                        /* Read one more byte so we can detect whether the content of the
                         * file has already changed or the guessed size for files from /proc
                         * wasn't large enough . */
                        k = read(fd, buf, size + 1);
                        if (k >= 0) {
                                n = k;
                                break;
                        }

                        if (errno != EINTR)
                                return -errno;
                }

                /* Consider a short read as EOF */
                if (n <= size)
                        break;

                /* If a maximum size is specified and we already read more we know the file is larger, and
                 * can handle this as truncation case. Note that if the size of what we read equals the
                 * maximum size then this doesn't mean truncation, the file might or might not end on that
                 * byte. We need to rerun the loop in that case, with a larger buffer size, so that we read
                 * at least one more byte to be able to distinguish EOF from truncation. */
                if (max_size != SIZE_MAX && n > max_size) {
                        n = size; /* Make sure we never use more than what we sized the buffer for (so that
                                   * we have one free byte in it for the trailing NUL we add below). */
                        truncated = true;
                        break;
                }

                /* We have no further attempts left? Then the file is apparently larger than our limits. Give up. */
                if (n_retries <= 0)
                        return -EFBIG;

                /* Hmm... either we read too few bytes from /proc or less likely the content of the file
                 * might have been changed (and is now bigger) while we were processing, let's try again
                 * either with the new file size. */

                if (lseek(fd, 0, SEEK_SET) < 0)
                        return -errno;

                buf = mfree(buf);
        }

        if (ret_contents) {

                /* Safety check: if the caller doesn't want to know the size of what we just read it will
                 * rely on the trailing NUL byte. But if there's an embedded NUL byte, then we should refuse
                 * operation as otherwise there'd be ambiguity about what we just read. */
                if (!ret_size && memchr(buf, 0, n))
                        return -EBADMSG;

                if (n < size) {
                        char *p;

                        /* Return rest of the buffer to libc */
                        p = realloc(buf, n + 1);
                        if (!p)
                                return -ENOMEM;
                        buf = p;
                }

                buf[n] = 0;
                *ret_contents = TAKE_PTR(buf);
        }

        if (ret_size)
                *ret_size = n;

        return !truncated;
}

int read_virtual_file_at(
                int dir_fd,
                const char *filename,
                size_t max_size,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        if (!filename) {
                if (dir_fd == AT_FDCWD)
                        return -EBADF;

                return read_virtual_file_fd(dir_fd, max_size, ret_contents, ret_size);
        }

        fd = openat(dir_fd, filename, O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return read_virtual_file_fd(fd, max_size, ret_contents, ret_size);
}

int
read_full_stream(FILE *f, char **contents, size_t *size)
{
	size_t n, l;
	_cleanup_free_ char *buf = NULL;
	struct stat st;

	assert(f);
	assert(contents);

	if (fstat(fileno(f), &st) < 0)
		return -errno;

	n = LINE_MAX;

	if (S_ISREG(st.st_mode)) {
		/* Safety check */
		if (st.st_size > 4 * 1024 * 1024)
			return -E2BIG;

		/* Start with the right file size, but be prepared for
                 * files from /proc which generally report a file size
                 * of 0 */
		if (st.st_size > 0)
			n = st.st_size;
	}

	l = 0;
	for (;;) {
		char *t;
		size_t k;

		t = realloc(buf, n + 1);
		if (!t)
			return -ENOMEM;

		buf = t;
		k = fread(buf + l, 1, n - l, f);

		if (k <= 0) {
			if (ferror(f))
				return -errno;

			break;
		}

		l += k;
		n *= 2;

		/* Safety check */
		if (n > 4 * 1024 * 1024)
			return -E2BIG;
	}

	buf[l] = 0;
	*contents = buf;
	buf = NULL; /* do not free */

	if (size)
		*size = l;

	return 0;
}

int
read_full_file(const char *fn, char **contents, size_t *size)
{
	_cleanup_fclose_ FILE *f = NULL;

	assert(fn);
	assert(contents);

	f = fopen(fn, "re");
	if (!f)
		return -errno;

	return read_full_stream(f, contents, size);
}

static int
parse_env_file_internal(FILE *f, const char *fname, const char *newline,
	int (*push)(const char *filename, unsigned line, const char *key,
		char *value, void *userdata, int *n_pushed),
	void *userdata, int *n_pushed)
{
	_cleanup_free_ char *contents = NULL, *key = NULL;
	size_t n_key = 0, n_value = 0,
	       last_value_whitespace = (size_t)-1,
	       last_key_whitespace = (size_t)-1;
	char *p, *value = NULL;
	int r;
	unsigned line = 1;

	enum {
		PRE_KEY,
		KEY,
		PRE_VALUE,
		VALUE,
		VALUE_ESCAPE,
		SINGLE_QUOTE_VALUE,
		SINGLE_QUOTE_VALUE_ESCAPE,
		DOUBLE_QUOTE_VALUE,
		DOUBLE_QUOTE_VALUE_ESCAPE,
		COMMENT,
		COMMENT_ESCAPE
	} state = PRE_KEY;

	assert(newline);

	if (f)
		r = read_full_stream(f, &contents, NULL);
	else
		r = read_full_file(fname, &contents, NULL);
	if (r < 0)
		return r;

	for (p = contents; *p; p++) {
		char c = *p;

		switch (state) {
		case PRE_KEY:
			if (strchr(COMMENTS, c))
				state = COMMENT;
			else if (!strchr(WHITESPACE, c)) {
				state = KEY;
				last_key_whitespace = (size_t)-1;

				if (!GREEDY_REALLOC(key,
					    n_key + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				key[n_key++] = c;
			}
			break;

		case KEY:
			if (strchr(newline, c)) {
				state = PRE_KEY;
				line++;
				n_key = 0;
			} else if (c == '=') {
				state = PRE_VALUE;
				last_value_whitespace = (size_t)-1;
			} else {
				if (!strchr(WHITESPACE, c))
					last_key_whitespace = (size_t)-1;
				else if (last_key_whitespace == (size_t)-1)
					last_key_whitespace = n_key;

				if (!GREEDY_REALLOC(key,
					    n_key + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				key[n_key++] = c;
			}

			break;

		case PRE_VALUE:
			if (strchr(newline, c)) {
				state = PRE_KEY;
				line++;
				key[n_key] = 0;

				if (value)
					value[n_value] = 0;

				/* strip trailing whitespace from key */
				if (last_key_whitespace != (size_t)-1)
					key[last_key_whitespace] = 0;

				r = push(fname, line, key, value, userdata,
					n_pushed);
				if (r < 0)
					goto fail;

				n_key = 0;
				value = NULL;
				n_value = 0;

			} else if (c == '\'')
				state = SINGLE_QUOTE_VALUE;
			else if (c == '\"')
				state = DOUBLE_QUOTE_VALUE;
			else if (c == '\\')
				state = VALUE_ESCAPE;
			else if (!strchr(WHITESPACE, c)) {
				state = VALUE;

				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}

			break;

		case VALUE:
			if (strchr(newline, c)) {
				state = PRE_KEY;
				line++;

				key[n_key] = 0;

				if (value)
					value[n_value] = 0;

				/* Chomp off trailing whitespace from value */
				if (last_value_whitespace != (size_t)-1)
					value[last_value_whitespace] = 0;

				/* strip trailing whitespace from key */
				if (last_key_whitespace != (size_t)-1)
					key[last_key_whitespace] = 0;

				r = push(fname, line, key, value, userdata,
					n_pushed);
				if (r < 0)
					goto fail;

				n_key = 0;
				value = NULL;
				n_value = 0;

			} else if (c == '\\') {
				state = VALUE_ESCAPE;
				last_value_whitespace = (size_t)-1;
			} else {
				if (!strchr(WHITESPACE, c))
					last_value_whitespace = (size_t)-1;
				else if (last_value_whitespace == (size_t)-1)
					last_value_whitespace = n_value;

				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}

			break;

		case VALUE_ESCAPE:
			state = VALUE;

			if (!strchr(newline, c)) {
				/* Escaped newlines we eat up entirely */
				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}
			break;

		case SINGLE_QUOTE_VALUE:
			if (c == '\'')
				state = PRE_VALUE;
			else if (c == '\\')
				state = SINGLE_QUOTE_VALUE_ESCAPE;
			else {
				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}

			break;

		case SINGLE_QUOTE_VALUE_ESCAPE:
			state = SINGLE_QUOTE_VALUE;

			if (!strchr(newline, c)) {
				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}
			break;

		case DOUBLE_QUOTE_VALUE:
			if (c == '\"')
				state = PRE_VALUE;
			else if (c == '\\')
				state = DOUBLE_QUOTE_VALUE_ESCAPE;
			else {
				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}

			break;

		case DOUBLE_QUOTE_VALUE_ESCAPE:
			state = DOUBLE_QUOTE_VALUE;

			if (!strchr(newline, c)) {
				if (!GREEDY_REALLOC(value,
					    n_value + 2)) {
					r = -ENOMEM;
					goto fail;
				}

				value[n_value++] = c;
			}
			break;

		case COMMENT:
			if (c == '\\')
				state = COMMENT_ESCAPE;
			else if (strchr(newline, c)) {
				state = PRE_KEY;
				line++;
			}
			break;

		case COMMENT_ESCAPE:
			state = COMMENT;
			break;
		}
	}

	if (state == PRE_VALUE || state == VALUE || state == VALUE_ESCAPE ||
		state == SINGLE_QUOTE_VALUE ||
		state == SINGLE_QUOTE_VALUE_ESCAPE ||
		state == DOUBLE_QUOTE_VALUE ||
		state == DOUBLE_QUOTE_VALUE_ESCAPE) {
		key[n_key] = 0;

		if (value)
			value[n_value] = 0;

		if (state == VALUE)
			if (last_value_whitespace != (size_t)-1)
				value[last_value_whitespace] = 0;

		/* strip trailing whitespace from key */
		if (last_key_whitespace != (size_t)-1)
			key[last_key_whitespace] = 0;

		r = push(fname, line, key, value, userdata, n_pushed);
		if (r < 0)
			goto fail;
	}

	return 0;

fail:
	free(value);
	return r;
}

static int
load_env_file_push(const char *filename, unsigned line, const char *key,
	char *value, void *userdata, int *n_pushed)
{
	char ***m = userdata;
	char *p;
	int r;

	if (!utf8_is_valid(key)) {
		_cleanup_free_ char *t = utf8_escape_invalid(key);

		log_error("%s:%u: invalid UTF-8 for key '%s', ignoring.",
			strna(filename), line, t);
		return -EINVAL;
	}

	if (value && !utf8_is_valid(value)) {
		_cleanup_free_ char *t = utf8_escape_invalid(value);

		log_error(
			"%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
			strna(filename), line, key, t);
		return -EINVAL;
	}

	p = strjoin(key, "=", strempty(value), NULL);
	if (!p)
		return -ENOMEM;

	r = strv_consume(m, p);
	if (r < 0)
		return r;

	if (n_pushed)
		(*n_pushed)++;

	free(value);
	return 0;
}

int
load_env_file(FILE *f, const char *fname, const char *newline, char ***rl)
{
	char **m = NULL;
	int r;

	if (!newline)
		newline = NEWLINE;

	r = parse_env_file_internal(f, fname, newline, load_env_file_push, &m,
		NULL);
	if (r < 0) {
		strv_free(m);
		return r;
	}

	*rl = m;
	return 0;
}

static int
load_env_file_push_pairs(const char *filename, unsigned line, const char *key,
	char *value, void *userdata, int *n_pushed)
{
	char ***m = userdata;
	int r;

	if (!utf8_is_valid(key)) {
		_cleanup_free_ char *t = utf8_escape_invalid(key);

		log_error("%s:%u: invalid UTF-8 for key '%s', ignoring.",
			strna(filename), line, t);
		return -EINVAL;
	}

	if (value && !utf8_is_valid(value)) {
		_cleanup_free_ char *t = utf8_escape_invalid(value);

		log_error(
			"%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
			strna(filename), line, key, t);
		return -EINVAL;
	}

	r = strv_extend(m, key);
	if (r < 0)
		return -ENOMEM;

	if (!value) {
		r = strv_extend(m, "");
		if (r < 0)
			return -ENOMEM;
	} else {
		r = strv_push(m, value);
		if (r < 0)
			return r;
	}

	if (n_pushed)
		(*n_pushed)++;

	return 0;
}

int
load_env_file_pairs(FILE *f, const char *fname, const char *newline, char ***rl)
{
	char **m = NULL;
	int r;

	if (!newline)
		newline = NEWLINE;

	r = parse_env_file_internal(f, fname, newline, load_env_file_push_pairs,
		&m, NULL);
	if (r < 0) {
		strv_free(m);
		return r;
	}

	*rl = m;
	return 0;
}

static void
write_env_var(FILE *f, const char *v)
{
	const char *p;

	p = strchr(v, '=');
	if (!p) {
		/* Fallback */
		fputs(v, f);
		fputc('\n', f);
		return;
	}

	p++;
	fwrite(v, 1, p - v, f);

	if (string_has_cc(p, NULL) ||
		chars_intersect(p, WHITESPACE SHELL_NEED_QUOTES)) {
		fputc('\"', f);

		for (; *p; p++) {
			if (strchr(SHELL_NEED_ESCAPE, *p))
				fputc('\\', f);

			fputc(*p, f);
		}

		fputc('\"', f);
	} else
		fputs(p, f);

	fputc('\n', f);
}

int
write_env_file(const char *fname, char **l)
{
	_cleanup_fclose_ FILE *f = NULL;
	_cleanup_free_ char *p = NULL;
	char **i;
	int r;

	assert(fname);

	r = fopen_temporary(fname, &f, &p);
	if (r < 0)
		return r;

	fchmod_umask(fileno(f), 0644);

	STRV_FOREACH (i, l)
		write_env_var(f, *i);

	r = fflush_and_check(f);
	if (r >= 0) {
		if (rename(p, fname) >= 0)
			return 0;

		r = -errno;
	}

	unlink(p);
	return r;
}

int
executable_is_script(const char *path, char **interpreter)
{
	int r;
	_cleanup_free_ char *line = NULL;
	int len;
	char *ans;

	assert(path);

	r = read_one_line_file(path, &line);
	if (r < 0)
		return r;

	if (!startswith(line, "#!"))
		return 0;

	ans = strstrip(line + 2);
	len = strcspn(ans, " \t");

	if (len == 0)
		return 0;

	ans = strndup(ans, len);
	if (!ans)
		return -ENOMEM;

	*interpreter = ans;
	return 1;
}

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should start with '\n' and end with a ':'. Whitespace and zeros
 * after the ':' will be skipped. field must be freed afterwards.
 */
int
get_status_field(const char *filename, const char *pattern, char **field)
{
	_cleanup_free_ char *status = NULL;
	char *t;
	size_t len;
	int r;

	assert(filename);
	assert(pattern);
	assert(field);

	r = read_full_file(filename, &status, NULL);
	if (r < 0)
		return r;

	t = strstr(status, pattern);
	if (!t)
		return -ENOENT;

	t += strlen(pattern);
	if (*t) {
		t += strspn(t, " \t");

		/* Also skip zeros, because when this is used for
                 * capabilities, we don't want the zeros. This way the
                 * same capability set always maps to the same string,
                 * irrespective of the total capability set size. For
                 * other numbers it shouldn't matter. */
		t += strspn(t, "0");
		/* Back off one char if there's nothing but whitespace
                   and zeros */
		if (!*t || isspace(*t))
			t--;
	}

	len = strcspn(t, WHITESPACE);

	*field = strndup(t, len);
	if (!*field)
		return -ENOMEM;

	return 0;
}

static inline void
funlockfilep(FILE **f)
{
	funlockfile(*f);
}

int
read_line(FILE *f, size_t limit, char **ret)
{
	_cleanup_free_ char *buffer = NULL;
	size_t n = 0, count = 0;

	assert(f);

	/* Something like a bounded version of getline().
         *
         * Considers EOF, \n and \0 end of line delimiters, and does not include these delimiters in the string
         * returned.
         *
         * Returns the number of bytes read from the files (i.e. including delimiters — this hence usually differs from
         * the number of characters in the returned string). When EOF is hit, 0 is returned.
         *
         * The input parameter limit is the maximum numbers of characters in the returned string, i.e. excluding
         * delimiters. If the limit is hit we fail and return -ENOBUFS.
         *
         * If a line shall be skipped ret may be initialized as NULL. */

	if (ret) {
		if (!GREEDY_REALLOC(buffer, 1))
			return -ENOMEM;
	}

	{
		_cleanup_(funlockfilep) FILE *flocked = f;
		flockfile(f);

		for (;;) {
			int c;

			if (n >= limit)
				return -ENOBUFS;

			errno = 0;
			c = fgetc(f);
			if (c == EOF) {
				/* if we read an error, and have no data to return, then propagate the error */
				if (ferror(f) && n == 0)
					return errno > 0 ? -errno : -EIO;

				break;
			}

			count++;

			if (IN_SET(c, '\n', 0)) /* Reached a delimiter */
				break;

			if (ret) {
				if (!GREEDY_REALLOC(buffer, n + 2))
					return -ENOMEM;

				buffer[n] = (char)c;
			}

			n++;
		}
	}

	if (ret) {
		buffer[n] = 0;

		*ret = buffer;
		buffer = NULL;
	}

	return (int)count;
}

int fdopen_unlocked(int fd, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fdopen(fd, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

int take_fdopen_unlocked(int *fd, const char *options, FILE **ret) {
        int r;

        assert(fd);

        r = fdopen_unlocked(*fd, options, ret);
        if (r < 0)
                return r;

        *fd = -EBADF;

        return 0;
}

FILE* take_fdopen(int *fd, const char *options) {
        assert(fd);

        FILE *f = fdopen(*fd, options);
        if (!f)
                return NULL;

        *fd = -EBADF;

        return f;
}

FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc) {
        FILE *f = open_memstream(ptr, sizeloc);
        if (!f)
                return NULL;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return f;
}

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should not include whitespace or the delimiter (':'). pattern matches only
 * the beginning of a line. Whitespace before ':' is skipped. Whitespace and
 * zeros after the ':' will be skipped. field must be freed afterwards.
 * terminator specifies the terminating characters of the field value (not
 * included in the value).
 */
int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field) {
        _cleanup_free_ char *status = NULL;
        char *t, *f;
        int r;

        assert(terminator);
        assert(filename);
        assert(pattern);
        assert(field);

        r = read_full_virtual_file(filename, &status, NULL);
        if (r < 0)
                return r;

        t = status;

        do {
                bool pattern_ok;

                do {
                        t = strstr(t, pattern);
                        if (!t)
                                return -ENOENT;

                        /* Check that pattern occurs in beginning of line. */
                        pattern_ok = (t == status || t[-1] == '\n');

                        t += strlen(pattern);

                } while (!pattern_ok);

                t += strspn(t, " \t");
                if (!*t)
                        return -ENOENT;

        } while (*t != ':');

        t++;

        if (*t) {
                t += strspn(t, " \t");

                /* Also skip zeros, because when this is used for
                 * capabilities, we don't want the zeros. This way the
                 * same capability set always maps to the same string,
                 * irrespective of the total capability set size. For
                 * other numbers it shouldn't matter. */
                t += strspn(t, "0");
                /* Back off one char if there's nothing but whitespace
                   and zeros */
                if (!*t || isspace(*t))
                        t--;
        }

        f = strdupcspn(t, terminator);
        if (!f)
                return -ENOMEM;

        *field = f;
        return 0;
}
