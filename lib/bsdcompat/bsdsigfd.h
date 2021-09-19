/*
 * Copyright (c) 2021
 *	David MacKay.  All rights reserved.
 */
/*
 * Minimal implementation of a signalfd-like interface in terms of KQueue.
 *  - only one signalfd per process is allowed.
 *  - OpenBSD (and macOS) support is wanting (no sigtimedwait.)
 *    - wrt macOS, is it true nested kqueues don't work (always return ready?)
 *  - no idea of interactions with pthreads
 *  - doesn't alter signal disposition. SIGCHLD etc must have
 *  non-SIG_DFL/SIG_IGN handlers or they won't be gotten by this mechanism.
 */

#ifndef BSDSIGFD_H_
#define BSDSIGFD_H_

#include <signal.h>

#include "svc-config.h"

#ifdef SVC_HAVE_signalfd
#include <sys/signalfd.h>

#define sigfd signalfd
#define sigfd_siginfo signalfd_siginfo
#define sigfd_read signalfd_read
#else

enum {
	SIGFD_NONBLOCK = 1,
	SIGFD_CLOEXEC = 2,
};

struct sigfd_siginfo {
	int ssi_signo;
	int ssi_pid;
};

int sigfd(int fd, const sigset_t *mask, int flags);
ssize_t sigfd_read(int fd, void *buf, size_t nbytes);
#endif /* SVC_HAVE_signalfd */

#endif /* BSDSIGFD_H_ */
