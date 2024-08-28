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

int pidref_set_pidfd(PidRef *pidref, int fd) {
        int r;

        assert(pidref);

        if (fd < 0)
                return -EBADF;

        int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0) {
                pid_t pid;

                if (!ERRNO_IS_RESOURCE(errno))
                        return -errno;

                /* Graceful fallback if we are out of fds */
                r = pidfd_get_pid(fd, &pid);
                if (r < 0)
                        return r;

                *pidref = PIDREF_MAKE_FROM_PID(pid);
                return 0;
        }

        return pidref_set_pidfd_consume(pidref, fd_copy);
}

int pidref_set_pidfd_take(PidRef *pidref, int fd) {
        pid_t pid;
        int r;

        assert(pidref);

        if (fd < 0)
                return -EBADF;

        r = pidfd_get_pid(fd, &pid);
        if (r < 0)
                return r;

        *pidref = (PidRef) {
                .fd = fd,
                .pid = pid,
        };

        return 0;
}

int pidref_set_pidfd_consume(PidRef *pidref, int fd) {
        int r;

        r = pidref_set_pidfd_take(pidref, fd);
        if (r < 0)
                safe_close(fd);

        return r;
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

int pidref_verify(const PidRef *pidref) {
        int r;

        /* This is a helper that is supposed to be called after reading information from procfs via a
         * PidRef. It ensures that the PID we track still matches the PIDFD we pin. If this value differs
         * after a procfs read, we might have read the data from a recycled PID. */

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->pid == 1)
                return 1; /* PID 1 can never go away, hence never be recycled to a different process → return 1 */

        if (pidref->fd < 0)
                return 0; /* If we don't have a pidfd we cannot validate it, hence we assume it's all OK → return 0 */

        r = pidfd_verify_pid(pidref->fd, pidref->pid);
        if (r < 0)
                return r;

        return 1; /* We have a pidfd and it still points to the PID we have, hence all is *really* OK → return 1 */
}
