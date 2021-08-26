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

#include "fdset.h"

int close_all_fds(const int except[], unsigned n_except)
{
	DIR *d;
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
		for (fd = 3; fd < (int) rl.rlim_max; fd++) {

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

		if (ignore_file(de->d_name))
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

	closedir(d);
	return r;
}

int fdset_new_fill(FDSet **_s) {
        DIR *d;
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

                if (ignore_file(de->d_name))
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
        closedir(d);

        /* We won't close the fds here! */
        if (s)
                set_free(MAKE_SET(s));

        return r;
}