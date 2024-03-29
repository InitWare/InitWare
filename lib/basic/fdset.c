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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "fdset.h"
#include "macro.h"
#include "sd-daemon.h"
#include "set.h"
#include "util.h"

/* Make sure we can distuingish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd) + 1)
#define PTR_TO_FD(p) (PTR_TO_INT(p) - 1)

FDSet *
fdset_new(void)
{
	return MAKE_FDSET(set_new(NULL));
}

int
fdset_new_array(FDSet **ret, int *fds, unsigned n_fds)
{
	unsigned i;
	FDSet *s;
	int r;

	assert(ret);

	s = fdset_new();
	if (!s)
		return -ENOMEM;

	for (i = 0; i < n_fds; i++) {
		r = fdset_put(s, fds[i]);
		if (r < 0) {
			set_free(MAKE_SET(s));
			return r;
		}
	}

	*ret = s;
	return 0;
}

FDSet *
fdset_free(FDSet *s)
{
	void *p;

	while ((p = set_steal_first(MAKE_SET(s)))) {
		/* Valgrind's fd might have ended up in this set here,
                 * due to fdset_new_fill(). We'll ignore all failures
                 * here, so that the EBADFD that valgrind will return
                 * us on close() doesn't influence us */

		/* When reloading duplicates of the private bus
                 * connection fds and suchlike are closed here, which
                 * has no effect at all, since they are only
                 * duplicates. So don't be surprised about these log
                 * messages. */

		log_debug("Closing left-over fd %i", PTR_TO_FD(p));
		close_nointr(PTR_TO_FD(p));
	}

	set_free(MAKE_SET(s));
	return NULL;
}

int
fdset_put(FDSet *s, int fd)
{
	assert(s);
	assert(fd >= 0);

	return set_put(MAKE_SET(s), FD_TO_PTR(fd));
}

int
fdset_consume(FDSet *s, int fd)
{
	int r;

	assert(s);
	assert(fd >= 0);

	r = fdset_put(s, fd);
	if (r <= 0)
		safe_close(fd);

	return r;
}

int
fdset_put_dup(FDSet *s, int fd)
{
	int copy, r;

	assert(s);
	assert(fd >= 0);

	copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (copy < 0)
		return -errno;

	r = fdset_put(s, copy);
	if (r < 0) {
		safe_close(copy);
		return r;
	}

	return copy;
}

bool
fdset_contains(FDSet *s, int fd)
{
	assert(s);
	assert(fd >= 0);

	return !!set_get(MAKE_SET(s), FD_TO_PTR(fd));
}

int
fdset_remove(FDSet *s, int fd)
{
	assert(s);
	assert(fd >= 0);

	return set_remove(MAKE_SET(s), FD_TO_PTR(fd)) ? fd : -ENOENT;
}

int
fdset_cloexec(FDSet *fds, bool b)
{
	Iterator i;
	void *p;
	int r;

	assert(fds);

	SET_FOREACH (p, MAKE_SET(fds), i)
		if ((r = fd_cloexec(PTR_TO_FD(p), b)) < 0)
			return r;

	return 0;
}

int
fdset_close_others(FDSet *fds)
{
	void *e;
	Iterator i;
	int *a;
	unsigned j, m;

	j = 0, m = fdset_size(fds);
	a = alloca(sizeof(int) * m);
	SET_FOREACH (e, MAKE_SET(fds), i)
		a[j++] = PTR_TO_FD(e);

	assert(j == m);

	return close_all_fds(a, j);
}

unsigned
fdset_size(FDSet *fds)
{
	return set_size(MAKE_SET(fds));
}

bool
fdset_isempty(FDSet *fds)
{
	return set_isempty(MAKE_SET(fds));
}

int
fdset_iterate(FDSet *s, Iterator *i)
{
	void *p;

	p = set_iterate(MAKE_SET(s), i);
	if (!p)
		return -ENOENT;

	return PTR_TO_FD(p);
}

int
fdset_steal_first(FDSet *fds)
{
	void *p;

	p = set_steal_first(MAKE_SET(fds));
	if (!p)
		return -ENOENT;

	return PTR_TO_FD(p);
}
