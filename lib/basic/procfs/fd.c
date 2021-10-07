/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright: systemd authors
 */

#include "fdset.h"
#include "util.h"

int
close_all_fds(const int except[], unsigned n_except)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;

	assert(n_except == 0 || except);

	d = opendir("/proc/self/fd");
	if (!d) {
		int fd;
		struct rlimit rl;

		/* When /proc isn't available (for example in chroots)
                 * the fallback is brute forcing through the fd
                 * table */

		assert_se(getrlimit(RLIMIT_NOFILE, &rl) >= 0);
		for (fd = 3; fd < (int)rl.rlim_max; fd++) {
			if (fd_in_set(fd, except, n_except))
				continue;

			if (close_nointr(fd) < 0)
				if (errno != EBADF && r == 0)
					r = -errno;
		}

		return r;
	}

	while ((de = readdir(d))) {
		int fd = -1;

		if (hidden_file(de->d_name))
			continue;

		if (safe_atoi(de->d_name, &fd) < 0)
			/* Let's better ignore this, just in case */
			continue;

		if (fd < 3)
			continue;

		if (fd == dirfd(d))
			continue;

		if (fd_in_set(fd, except, n_except))
			continue;

		if (close_nointr(fd) < 0) {
			/* Valgrind has its own FD and doesn't want to have it closed */
			if (errno != EBADF && r == 0)
				r = -errno;
		}
	}

	return r;
}

int
fdset_new_fill(FDSet **_s)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;
	FDSet *s;

	assert(_s);

	/* Creates an fdset and fills in all currently open file
         * descriptors. */

	d = opendir("/proc/self/fd");
	if (!d)
		return -errno;

	s = fdset_new();
	if (!s) {
		r = -ENOMEM;
		goto finish;
	}

	while ((de = readdir(d))) {
		int fd = -1;

		if (hidden_file(de->d_name))
			continue;

		r = safe_atoi(de->d_name, &fd);
		if (r < 0)
			goto finish;

		if (fd < 3)
			continue;

		if (fd == dirfd(d))
			continue;

		r = fdset_put(s, fd);
		if (r < 0)
			goto finish;
	}

	r = 0;
	*_s = s;
	s = NULL;

finish:
	/* We won't close the fds here! */
	if (s)
		set_free(MAKE_SET(s));

	return r;
}