/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stat-util.h"

#include "svc-config.h"

#ifdef HAVE_PIDFD_OPEN
#include <sys/pidfd.h>
#endif

bool pidref_equal(const PidRef *a, const PidRef *b) {
        int r;

        if (pidref_is_set(a)) {
                if (!pidref_is_set(b))
                        return false;

                if (a->pid != b->pid)
                        return false;

                if (a->fd < 0 || b->fd < 0)
                        return true;

                /* pidfds live in their own pidfs and each process comes with a unique inode number since
                 * kernel 6.8. We can safely do this on older kernels too though, as previously anonymous
                 * inode was used and inode number was the same for all pidfds. */
                r = fd_inode_same(a->fd, b->fd);
                if (r < 0)
                        log_debug_errno(r, "Failed to check whether pidfds for pid " PID_FMT " are equal, assuming yes: %m",
                                        a->pid);
                return r != 0;
        }

        return !pidref_is_set(b);
}

int pidref_set_pid(PidRef *pidref, pid_t pid) {
        int fd;

        assert(pidref);

        if (pid < 0)
                return -ESRCH;
        if (pid == 0)
                pid = getpid_cached();
        fd = pidfd_open(pid, 0);
        if (fd < 0) {
                /* Graceful fallback in case the kernel doesn't support pidfds or is out of fds */
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno) && !ERRNO_IS_RESOURCE(errno))
                        return log_debug_errno(errno, "Failed to open pidfd for pid " PID_FMT ": %m", pid);

                fd = -EBADF;
        }

        *pidref = (PidRef) {
                .fd = fd,
                .pid = pid,
        };

        return 0;
}

void pidref_done(PidRef *pidref) {
        assert(pidref);

        *pidref = (PidRef) {
                .fd = safe_close(pidref->fd),
        };
}

PidRef *pidref_free(PidRef *pidref) {
        /* Regularly, this is an embedded structure. But sometimes we want it on the heap too */
        if (!pidref)
                return NULL;

        pidref_done(pidref);
        return mfree(pidref);
}
