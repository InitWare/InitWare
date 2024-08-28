/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here

#include <dirent.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"

#define EXIT_SKIP_REMAINING 77

static int do_spawn(
                const char *path,
                char *argv[],
                int stdout_fd,
                bool set_systemd_exec_pid,
                pid_t *ret_pid) {

        int r;

        assert(path);
        assert(ret_pid);

        if (null_or_empty_path(path) > 0) {
                log_debug("%s is empty (a mask).", path);
                return 0;
        }

        pid_t pid;
        r = safe_fork_full(
                        "(direxec)",
                        (const int[]) { STDIN_FILENO, stdout_fd < 0 ? STDOUT_FILENO : stdout_fd, STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO|FORK_CLOSE_ALL_FDS,
                        &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                char *_argv[2];

                if (set_systemd_exec_pid) {
                        r = setenv_systemd_exec_pid(false);
                        if (r < 0)
                                log_warning_errno(r, "Failed to set $SYSTEMD_EXEC_PID, ignoring: %m");
                }

                if (!argv) {
                        _argv[0] = (char*) path;
                        _argv[1] = NULL;
                        argv = _argv;
                } else
                        argv[0] = (char*) path;

                execv(path, argv);
                log_error_errno(errno, "Failed to execute %s: %m", path);
                _exit(EXIT_FAILURE);
        }

        *ret_pid = pid;
        return 1;
}

static int do_execute(
                char* const* paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                int output_fd,
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        bool parallel_execution;
        int r;

        /* We fork this all off from a child process so that we can somewhat cleanly make
         * use of SIGALRM to set a time limit.
         *
         * We attempt to perform parallel execution if configured by the user, however
         * if `callbacks` is nonnull, execution must be serial.
         */
        parallel_execution = FLAGS_SET(flags, EXEC_DIR_PARALLEL) && !callbacks;

        if (parallel_execution) {
                pids = hashmap_new(NULL);
                if (!pids)
                        return log_oom();
        }

        /* Abort execution of this process after the timeout. We simply rely on SIGALRM as
         * default action terminating the process, and turn on alarm(). */

        if (timeout != USEC_INFINITY)
                alarm(DIV_ROUND_UP(timeout, USEC_PER_SEC));

        STRV_FOREACH(e, envp)
                if (putenv(*e) != 0)
                        return log_error_errno(errno, "Failed to set environment variable: %m");

        STRV_FOREACH(path, paths) {
                _cleanup_free_ char *t = NULL;
                _cleanup_close_ int fd = -EBADF;
                pid_t pid;

                t = path_join(root, *path);
                if (!t)
                        return log_oom();

                if (callbacks) {
                        _cleanup_free_ char *bn = NULL;

                        r = path_extract_filename(*path, &bn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from path '%s': %m", *path);

                        fd = open_serialization_fd(bn);
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to open serialization file: %m");
                }

                // HACK: Undefined?
                // if (DEBUG_LOGGING) {
                //         _cleanup_free_ char *args = NULL;
                //         if (argv)
                //                 args = quote_command_line(strv_skip(argv, 1), SHELL_ESCAPE_EMPTY);

                //         log_debug("About to execute %s%s%s", t, argv ? " " : "", argv ? strnull(args) : "");
                // }

                r = do_spawn(t, argv, fd, FLAGS_SET(flags, EXEC_DIR_SET_SYSTEMD_EXEC_PID), &pid);
                if (r <= 0)
                        continue;

                if (parallel_execution) {
                        r = hashmap_put(pids, PID_TO_PTR(pid), t);
                        if (r < 0)
                                return log_oom();
                        t = NULL;
                } else {
                        bool skip_remaining = false;

                        r = wait_for_terminate_and_check(t, pid, WAIT_LOG_ABNORMAL);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                if (FLAGS_SET(flags, EXEC_DIR_SKIP_REMAINING) && r == EXIT_SKIP_REMAINING) {
                                        log_info("%s succeeded with exit status %i, not executing remaining executables.", *path, r);
                                        skip_remaining = true;
                                } else if (FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS))
                                        log_warning("%s failed with exit status %i, ignoring.", *path, r);
                                else {
                                        log_error("%s failed with exit status %i.", *path, r);
                                        return r;
                                }
                        }

                        if (callbacks) {
                                if (lseek(fd, 0, SEEK_SET) < 0)
                                        return log_error_errno(errno, "Failed to seek on serialization fd: %m");

                                r = callbacks[STDOUT_GENERATE](TAKE_FD(fd), callback_args[STDOUT_GENERATE]);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to process output from %s: %m", *path);
                        }

                        if (skip_remaining)
                                break;
                }
        }

        if (callbacks) {
                r = callbacks[STDOUT_COLLECT](output_fd, callback_args[STDOUT_COLLECT]);
                if (r < 0)
                        return log_error_errno(r, "Callback two failed: %m");
        }

        while (!hashmap_isempty(pids)) {
                _cleanup_free_ char *t = NULL;
                pid_t pid;

                pid = PTR_TO_PID(hashmap_first_key(pids));
                assert(pid > 0);

                t = hashmap_remove(pids, PID_TO_PTR(pid));
                assert(t);

                r = wait_for_terminate_and_check(t, pid, WAIT_LOG);
                if (r < 0)
                        return r;
                if (!FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS) && r > 0)
                        return r;
        }

        return 0;
}

int execute_strv(
                const char *name,
                char* const* paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_close_ int fd = -EBADF;
        pid_t executor_pid;
        int r;

        assert(!FLAGS_SET(flags, EXEC_DIR_PARALLEL | EXEC_DIR_SKIP_REMAINING));

        if (strv_isempty(paths))
                return 0;

        if (callbacks) {
                assert(name);
                assert(callback_args);
                assert(callbacks[STDOUT_GENERATE]);
                assert(callbacks[STDOUT_COLLECT]);
                assert(callbacks[STDOUT_CONSUME]);

                fd = open_serialization_fd(name);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open serialization file: %m");
        }

        /* Executes all binaries in the directories serially or in parallel and waits for
         * them to finish. Optionally a timeout is applied. If a file with the same name
         * exists in more than one directory, the earliest one wins. */

        r = safe_fork("(sd-exec-strv)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &executor_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                r = do_execute(paths, root, timeout, callbacks, callback_args, fd, argv, envp, flags);
                _exit(r < 0 ? EXIT_FAILURE : r);
        }

        r = wait_for_terminate_and_check("(sd-exec-strv)", executor_pid, 0);
        if (r < 0)
                return r;
        if (!FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS) && r > 0)
                return r;

        if (!callbacks)
                return 0;

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to rewind serialization fd: %m");

        r = callbacks[STDOUT_CONSUME](TAKE_FD(fd), callback_args[STDOUT_CONSUME]);
        if (r < 0)
                return log_error_errno(r, "Failed to parse returned data: %m");
        return 0;
}

int execute_directories(
                const char* const* directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_strv_free_ char **paths = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(!strv_isempty((char**) directories));

        r = conf_files_list_strv(&paths, NULL, NULL, CONF_FILES_EXECUTABLE|CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, directories);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate executables: %m");

        if (strv_isempty(paths)) {
                log_debug("No executables found.");
                return 0;
        }

        if (callbacks) {
                r = path_extract_filename(directories[0], &name);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", directories[0]);
        }

        return execute_strv(name, paths, NULL, timeout, callbacks, callback_args, argv, envp, flags);
}
