/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */
/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include <sys/param.h>

#include <assert.h>

#include "fdset.h"
#include "kvm.h"
#include "set.h"

#ifdef HAVE_ulimit_h
#include <ulimit.h>
#endif

#if defined(SVC_PLATFORM_FreeBSD)
#include <libutil.h>
#define ki_fd kf_fd
#elif defined(SVC_PLATFORM_OpenBSD)
#define ki_fd fd_fd
#elif defined(SVC_PLATFORM_DragonFlyBSD)
#define ki_fd f_fd
#endif

#ifdef SVC_PLATFORM_NetBSD
struct kinfo_file *
get_files(int *cnt)
{
	size_t offset;
	size_t len;
	int mib[6];
	void *buf;

	mib[0] = CTL_KERN;
	mib[1] = KERN_FILE2;
	mib[2] = KERN_FILE_BYPID;
	mib[3] = getpid();
	mib[4] = sizeof(struct kinfo_file);
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
		return NULL;

	offset = len % sizeof(off_t);
	mib[5] = len / sizeof(struct kinfo_file);

	if ((buf = malloc(len + offset)) == NULL)
		return NULL;

	if (sysctl(mib, 6, buf + offset, &len, NULL, 0) == -1) {
		free(buf);
		return NULL;
	}

	offset = len % sizeof(off_t);
	*cnt = len / sizeof(struct kinfo_file);

	return buf;
}
#endif

int
close_all_fds(const int except[], unsigned n_except)
{
	int r = 0, fd_set;

	for (int fd = 3; fd < 1023; fd++) {
		if (fd_in_set(fd, except, n_except))
			continue;

		if (close_nointr(fd) < 0)
			if (errno != EBADF && r == 0)
				r = -errno;
	}

	return r;
}

int
fdset_new_fill(FDSet **out)
{
#if defined(SVC_PLATFORM_DragonFlyBSD)
	// TODO: use fdescfs, I think DragonFly BSD has it
	return -ENOTSUP;
#else
	int r = 0;
	FDSet *fdset;
	struct kinfo_file *files = NULL;
	int cnt;

	assert(out);

	fdset = fdset_new();
	if (!fdset) {
		r = -ENOMEM;
		goto finish;
	}

	/* avoid opening KVM on FreeBSD, otherwise it open()'s /dev/null twice */
#ifndef SVC_PLATFORM_FreeBSD
	if (!open_kvm())
		return -errno;
#endif

#if defined(SVC_PLATFORM_FreeBSD)
	files = kinfo_getfile(getpid(), &cnt);
#elif defined(SVC_PLATFORM_NetBSD)
	files = get_files(&cnt);
#elif defined(SVC_PLATFORM_OpenBSD)
	files = kvm_getfiles(g_kd, KERN_FILE_BYPID, getpid(),
		sizeof(struct kinfo_file), &cnt);
#endif

	if (!files)
		return -errno;

	for (int i = 0; i < cnt; i++) {
		int fd = files[i].ki_fd;

		if (fd < 3)
			continue;

		r = fdset_put(fdset, fd);
		if (r < 0)
			goto finish;
	}

	r = 0;
	*out = fdset;
	fdset = NULL;

finish:
#if defined(SVC_PLATFORM_FreeBSD) || defined(SVC_PLATFORM_NetBSD)
	/* real KVM manages its own memory */
	free(files);
#endif

	if (fdset)
		set_free(MAKE_SET(fdset));

	return r;
#endif
}
