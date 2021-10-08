/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */
/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include <sys/proc.h>
#include <libproc.h>

#include "fdset.h"
#include "util.h"

/* max of 1024 open files assumed */

int
close_all_fds(const int except[], unsigned n_except)
{
	struct proc_fdinfo fdinfo[1024];
	int fdcnt;
	int r = 0;

	fdcnt = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fdinfo,
		sizeof fdinfo);
	if (fdcnt < 0) {
		log_error("Failed to get process FD info: %m\n");
		return -errno;
	}

	fdcnt = fdcnt / PROC_PIDLISTFD_SIZE;

	for (int i = 0; i < fdcnt; i++) {
		int fd = fdinfo[i].proc_fd;

		if (fd_in_set(fd, except, n_except))
			continue;
		else if (fd < 3)
			continue;
		else if (close_nointr(fd) < 0)
			if (errno != EBADF && r == 0)
				r = -errno;
	}

	return r;
}

int
fdset_new_fill(FDSet **out)
{
	int r;
	FDSet *s;
	struct proc_fdinfo fdinfo[1024];
	int fdcnt;

	fdcnt = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fdinfo,
		sizeof fdinfo);
	if (fdcnt < 0) {
		log_error("Failed to get process FD info: %m\n");
		return -errno;
	}

	fdcnt = fdcnt / PROC_PIDLISTFD_SIZE;

	for (int i = 0; i < fdcnt; i++) {
		int fd = fdinfo[i].proc_fd;

		if (fd < 3)
			continue;

		r = fdset_put(s, fd);
		if (r < 0)
			goto finish;
	}

	s = fdset_new();
	if (!s) {
		r = -ENOMEM;
		goto finish;
	}

finish:
	if (s)
		set_free(MAKE_SET(s));
	return r;
}