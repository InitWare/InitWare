/*******************************************************************

    LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

    (c) 2021 David Mackay
        All rights reserved.
*********************************************************************/

#include <sys/param.h>

#include <assert.h>
#include <ulimit.h>

#include "fdset.h"
#include "kvm.h"
#include "set.h"

#if defined(Sys_Plat_FreeBSD)
#include <libutil.h>
#define ki_fd kf_fd
#elif defined(Sys_Plat_OpenBSD)
#define ki_fd fd_fd
#elif defined(Sys_Plat_DragonFlyBSD)
#define ki_fd f_fd
#endif

#ifdef Sys_Plat_NetBSD
struct kinfo_file *get_files(int *cnt)
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

int close_all_fds(const int except[], unsigned n_except)
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


int fdset_new_fill(FDSet **_s)
{
#if defined(Sys_Plat_DragonFlyBSD)
	return -ENOTSUP;
#else
	int r = 0;
	FDSet *s;
        struct kinfo_file *files = NULL;
        int cnt;

        assert(_s);

        s = fdset_new();
        if (!s) {
                r = -ENOMEM;
                goto finish;
        }

        /* avoid opening KVM on FreeBSD, otherwise it open()'s /dev/null twice */
#ifndef Sys_Plat_FreeBSD
        if (!open_kvm())
                return -errno;
#endif

#if defined(Sys_Plat_FreeBSD)
        files = kinfo_getfile(getpid(), &cnt);
#elif defined(Sys_Plat_NetBSD)
        files = get_files(&cnt);
#elif defined(Sys_Plat_OpenBSD)
	files = kvm_getfiles(g_kd, KERN_FILE_BYPID, getpid(), sizeof(struct kinfo_file), &cnt);
#endif

        if (!files)
                return -errno;

        for (int i = 0; i < cnt; i++) {
                int fd = files[i].ki_fd;

                if (fd < 3)
                        continue;

                r = fdset_put(s, fd);
                if (r < 0)
                        goto finish;
        }

        r = 0;
        *_s = s;
        s = NULL;

finish:
#if defined(Sys_Plat_FreeBSD) || defined(Sys_Plat_NetBSD)
        /* real KVM manages its own memory */
        free(files);
#endif

        if (s)
                set_free(MAKE_SET(s));

        return r;
#endif
}
