/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include "time-util.h"

typedef int (*gather_stdout_callback_t) (int fd, void *arg);

enum {
        STDOUT_GENERATE,   /* from generators to helper process */
        STDOUT_COLLECT,    /* from helper process to main process */
        STDOUT_CONSUME,    /* process data in main process */
        _STDOUT_CONSUME_MAX,
};

typedef enum {
        EXEC_DIR_NONE                 = 0,      /* No execdir flags */
        EXEC_DIR_PARALLEL             = 1 << 0, /* Execute scripts in parallel, if possible */
        EXEC_DIR_IGNORE_ERRORS        = 1 << 1, /* Ignore non-zero exit status of scripts */
        EXEC_DIR_SET_SYSTEMD_EXEC_PID = 1 << 2, /* Set $SYSTEMD_EXEC_PID environment variable */
        EXEC_DIR_SKIP_REMAINING       = 1 << 3, /* Ignore remaining executions when one exit with 77. */
} ExecDirFlags;

int execute_strv(
                const char *name,
                char* const* paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags);

int execute_directories(
                const char* const* directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags);
