/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>

int pid_get_comm(pid_t pid, char **ret);

int container_get_leader(const char *machine, pid_t *pid);

typedef enum WaitFlags {
        WAIT_LOG_ABNORMAL             = 1 << 0,
        WAIT_LOG_NON_ZERO_EXIT_STATUS = 1 << 1,

        /* A shortcut for requesting the most complete logging */
        WAIT_LOG = WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS,
} WaitFlags;

int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags);

void sigterm_wait(pid_t pid);

static inline bool pid_is_valid(pid_t p) {
        return p > 0;
}

pid_t getpid_cached(void);
void reset_cached_pid(void);

typedef enum ForkFlags {
        FORK_RESET_SIGNALS      = 1 <<  0, /* Reset all signal handlers and signal mask */
        FORK_CLOSE_ALL_FDS      = 1 <<  1, /* Close all open file descriptors in the child, except for 0,1,2 */
        FORK_DEATHSIG_SIGTERM   = 1 <<  2, /* Set PR_DEATHSIG in the child to SIGTERM */
        FORK_DEATHSIG_SIGINT    = 1 <<  3, /* Set PR_DEATHSIG in the child to SIGINT */
        FORK_DEATHSIG_SIGKILL   = 1 <<  4, /* Set PR_DEATHSIG in the child to SIGKILL */
        FORK_REARRANGE_STDIO    = 1 <<  5, /* Connect 0,1,2 to specified fds or /dev/null */
        FORK_REOPEN_LOG         = 1 <<  6, /* Reopen log connection */
        FORK_LOG                = 1 <<  7, /* Log above LOG_DEBUG log level about failures */
        FORK_WAIT               = 1 <<  8, /* Wait until child exited */
        FORK_NEW_MOUNTNS        = 1 <<  9, /* Run child in its own mount namespace                               💣 DO NOT USE IN THREADED PROGRAMS! 💣 */
        FORK_MOUNTNS_SLAVE      = 1 << 10, /* Make child's mount namespace MS_SLAVE */
        FORK_PRIVATE_TMP        = 1 << 11, /* Mount new /tmp/ in the child (combine with FORK_NEW_MOUNTNS!) */
        FORK_RLIMIT_NOFILE_SAFE = 1 << 12, /* Set RLIMIT_NOFILE soft limit to 1K for select() compat */
        FORK_STDOUT_TO_STDERR   = 1 << 13, /* Make stdout a copy of stderr */
        FORK_FLUSH_STDIO        = 1 << 14, /* fflush() stdout (and stderr) before forking */
        FORK_NEW_USERNS         = 1 << 15, /* Run child in its own user namespace                                💣 DO NOT USE IN THREADED PROGRAMS! 💣 */
        FORK_CLOEXEC_OFF        = 1 << 16, /* In the child: turn off O_CLOEXEC on all fds in except_fds[] */
        FORK_KEEP_NOTIFY_SOCKET = 1 << 17, /* Unless this specified, $NOTIFY_SOCKET will be unset. */
        FORK_DETACH             = 1 << 18, /* Double fork if needed to ensure PID1/subreaper is parent */
        FORK_NEW_NETNS          = 1 << 19, /* Run child in its own network namespace                             💣 DO NOT USE IN THREADED PROGRAMS! 💣 */
        FORK_PACK_FDS           = 1 << 20, /* Rearrange the passed FDs to be FD 3,4,5,etc. Updates the array in place (combine with FORK_CLOSE_ALL_FDS!) */
} ForkFlags;

int safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid);

static inline int safe_fork(const char *name, ForkFlags flags, pid_t *ret_pid) {
        return safe_fork_full(name, NULL, NULL, 0, flags, ret_pid);
}

#define TAKE_PID(pid) TAKE_GENERIC(pid, pid_t, 0)
