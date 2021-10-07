/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright: systemd authors
 */

#include <ctype.h>

#include "fileio.h"
#include "util.h"

int
get_parent_of_pid(pid_t pid, pid_t *_ppid)
{
	int r;
	_cleanup_free_ char *line = NULL;
	long unsigned ppid;
	const char *p;

	assert(pid >= 0);
	assert(_ppid);

	if (pid == 0) {
		*_ppid = getppid();
		return 0;
	}

	p = procfs_file_alloca(pid, "stat");
	r = read_one_line_file(p, &line);
	if (r < 0)
		return r;

	/* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

	p = strrchr(line, ')');
	if (!p)
		return -EIO;

	p++;

	if (sscanf(p,
		    " "
		    "%*c " /* state */
		    "%lu ", /* ppid */
		    &ppid) != 1)
		return -EIO;

	if ((long unsigned)(pid_t)ppid != ppid)
		return -ERANGE;

	*_ppid = (pid_t)ppid;

	return 0;
}

int
get_process_state(pid_t pid)
{
	const char *p;
	char state;
	int r;
	_cleanup_free_ char *line = NULL;

	assert(pid >= 0);

	p = procfs_file_alloca(pid, "stat");
	r = read_one_line_file(p, &line);
	if (r < 0)
		return r;

	p = strrchr(line, ')');
	if (!p)
		return -EIO;

	p++;

	if (sscanf(p, " %c", &state) != 1)
		return -EIO;

	return (unsigned char)state;
}

int
get_process_comm(pid_t pid, char **name)
{
	const char *p;
	int r;

	assert(name);
	assert(pid >= 0);

	p = procfs_file_alloca(pid, "comm");

	r = read_one_line_file(p, name);
	if (r == -ENOENT)
		return -ESRCH;

	return r;
}

int
get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback,
	char **line)
{
	_cleanup_fclose_ FILE *f = NULL;
	char *r = NULL, *k;
	const char *p;
	int c;

	assert(line);
	assert(pid >= 0);

	p = procfs_file_alloca(pid, "cmdline");

	f = fopen(p, "re");
	if (!f)
		return -errno;

	if (max_length == 0) {
		size_t len = 0, allocated = 0;

		while ((c = getc(f)) != EOF) {
			if (!GREEDY_REALLOC(r, allocated, len + 2)) {
				free(r);
				return -ENOMEM;
			}

			r[len++] = isprint(c) ? c : ' ';
		}

		if (len > 0)
			r[len - 1] = 0;

	} else {
		bool space = false;
		size_t left;

		r = new (char, max_length);
		if (!r)
			return -ENOMEM;

		k = r;
		left = max_length;
		while ((c = getc(f)) != EOF) {
			if (isprint(c)) {
				if (space) {
					if (left <= 4)
						break;

					*(k++) = ' ';
					left--;
					space = false;
				}

				if (left <= 4)
					break;

				*(k++) = (char)c;
				left--;
			} else
				space = true;
		}

		if (left <= 4) {
			size_t n = MIN(left - 1, 3U);
			memcpy(k, "...", n);
			k[n] = 0;
		} else
			*k = 0;
	}

	/* Kernel threads have no argv[] */
	if (isempty(r)) {
		_cleanup_free_ char *t = NULL;
		int h;

		free(r);

		if (!comm_fallback)
			return -ENOENT;

		h = get_process_comm(pid, &t);
		if (h < 0)
			return h;

		r = strjoin("[", t, "]", NULL);
		if (!r)
			return -ENOMEM;
	}

	*line = r;
	return 0;
}

static int
get_process_link_contents(const char *proc_file, char **name)
{
	int r;

	assert(proc_file);
	assert(name);

	r = readlink_malloc(proc_file, name);
	if (r < 0)
		return r == -ENOENT ? -ESRCH : r;

	return 0;
}
int
get_process_exe(pid_t pid, char **name)
{
	const char *p;
	char *d;
	int r;

	assert(pid >= 0);

	p = procfs_file_alloca(pid, "exe");
	r = get_process_link_contents(p, name);
	if (r < 0)
		return r;

	d = endswith(*name, " (deleted)");
	if (d)
		*d = '\0';

	return 0;
}

static int
get_process_id(pid_t pid, const char *field, uid_t *uid)
{
	_cleanup_fclose_ FILE *f = NULL;
	char line[LINE_MAX];
	const char *p;

	assert(field);
	assert(uid);

	if (pid == 0)
		return getuid();

	p = procfs_file_alloca(pid, "status");
	f = fopen(p, "re");
	if (!f)
		return -errno;

	FOREACH_LINE(line, f, return -errno)
	{
		char *l;

		l = strstrip(line);

		if (startswith(l, field)) {
			l += strlen(field);
			l += strspn(l, WHITESPACE);

			l[strcspn(l, WHITESPACE)] = 0;

			return parse_uid(l, uid);
		}
	}

	return -EIO;
}

int
get_process_uid(pid_t pid, uid_t *uid)
{
	return get_process_id(pid, "Uid:", uid);
}

int
get_process_gid(pid_t pid, gid_t *gid)
{
	assert_cc(sizeof(uid_t) == sizeof(gid_t));
	return get_process_id(pid, "Gid:", gid);
}
