/*
 * Copyright (c) 2021
 *	David MacKay.  All rights reserved.
 */

#include "bsdsigfd.h"

#ifndef SVC_HAVE_signalfd

#include <sys/event.h>

#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "bsdsignal.h"

static int sigfd_fd = -1;
static sigset_t sset;

int
sigfd(int fd, const sigset_t *set, int flags)
{
	struct kevent kev;
	int r;

	if (sigfd_fd != -1 || fd != -1) {
		errno = -EBUSY;
		return -1;
	}

	sigfd_fd = kqueue();
	if (sigfd_fd == -1)
		return -1;

	for (int i = 0; i < _NSIG; i++) {
		if (sigismember(set, i)) {
			EV_SET(&kev, i, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
			if (kevent(sigfd_fd, &kev, 1, NULL, 0, NULL) < 0) {
				r = -errno;
				goto fail;
			}
		}
	}

	sset = *set;

	return sigfd_fd;

fail:
	close(sigfd_fd);
	errno = -r;
	return -1;
}

ssize_t
sigfd_read(int fd, void *buf, size_t nbytes)
{
	struct kevent kev;
	siginfo_t siginfo;
	struct sigfd_siginfo *out = buf;
	struct timespec ts;
	int r;

	assert(nbytes == sizeof(struct sigfd_siginfo));
	assert(fd != -1);

	ts.tv_sec = ts.tv_nsec = 0;

	r = kevent(sigfd_fd, NULL, 0, &kev, 1, &ts);
	if (r < 0)
		return -1;
	else if (r > 0)
		assert(kev.filter == EVFILT_SIGNAL);

	if (sigtimedwait(&sset, &siginfo, &ts) < 0)
		return -1;

	/* these are adequate for now */
	out->ssi_signo = siginfo.si_signo;
	out->ssi_pid = siginfo.si_pid;

	return nbytes;
}

#endif