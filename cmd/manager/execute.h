/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

typedef struct ExecStatus ExecStatus;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;

#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include "list.h"
#include "util.h"

#ifdef Use_Libcap
#        include <sys/capability.h>
#endif

typedef struct PTGroup PTGroup;
typedef struct PTManager PTManager;
typedef struct Unit Unit;

typedef enum ExecInput {
        EXEC_INPUT_NULL,
        EXEC_INPUT_TTY,
        EXEC_INPUT_TTY_FORCE,
        EXEC_INPUT_TTY_FAIL,
        EXEC_INPUT_SOCKET,
        _EXEC_INPUT_MAX,
        _EXEC_INPUT_INVALID = -1
} ExecInput;

typedef enum ExecOutput {
        EXEC_OUTPUT_INHERIT,
        EXEC_OUTPUT_NULL,
        EXEC_OUTPUT_TTY,
        EXEC_OUTPUT_SYSLOG,
        EXEC_OUTPUT_SYSLOG_AND_CONSOLE,
        EXEC_OUTPUT_KMSG,
        EXEC_OUTPUT_KMSG_AND_CONSOLE,
        EXEC_OUTPUT_JOURNAL,
        EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
        EXEC_OUTPUT_SOCKET,
        _EXEC_OUTPUT_MAX,
        _EXEC_OUTPUT_INVALID = -1
} ExecOutput;

struct ExecStatus {
        dual_timestamp start_timestamp;
        dual_timestamp exit_timestamp;
        pid_t pid;
        int code;   /* as in siginfo_t::si_code */
        int status; /* as in sigingo_t::si_status */
};

struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status;
        IWLIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
        bool ignore;
};

struct ExecContext {
        char **environment;
        char **environment_files;

        struct rlimit *rlimit[RLIM_NLIMITS];
        char *working_directory, *root_directory;

        mode_t umask;

        int nice;

        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;

        char *tty_path;

        bool ignore_sigpipe;

        /* Since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only and in the child
         * process. */
        char *user;
        char *group;
        char **supplementary_groups;

        char *pam_name;

        char *utmp_id;

        char **read_write_dirs, **read_only_dirs, **inaccessible_dirs;
        unsigned long mount_flags;

        int syslog_priority;
        char *syslog_identifier;
        bool syslog_level_prefix;

        bool non_blocking;
        char *tmp_dir;
        char *var_tmp_dir;

        /* This is not exposed to the user but available
         * internally. We need it to make sure that whenever we spawn
         * /bin/mount it is run in the same process group as us so
         * that the autofs logic detects that it belongs to us and we
         * don't enter a trigger loop. */
        bool same_pgrp;

#ifdef Use_Libcap
        uint64_t capability_bounding_set_drop;

        cap_t capabilities;
        int secure_bits;
#endif

#ifdef Sys_Plat_Linux
        int oom_score_adjust;
        int ioprio;
        int cpu_sched_policy;
        int cpu_sched_priority;

        cpu_set_t *cpuset;
        unsigned cpuset_ncpus;
        nsec_t timer_slack_nsec;

        bool tty_reset;
        bool tty_vhangup;
        bool tty_vt_disallocate;

        bool cpu_sched_reset_on_fork;
        bool private_tmp;
        bool private_network;

        bool no_new_privileges;

        uint32_t *syscall_filter;
#endif

        bool nice_set : 1;

#ifdef Sys_Plat_Linux
        bool oom_score_adjust_set : 1;
        bool ioprio_set : 1;
        bool cpu_sched_set : 1;
#endif
};

#ifdef Sys_Plat_Linux
#        include "linux/cgroup.h"
#endif

int exec_spawn(
        ExecCommand *command,
        char **argv,
        ExecContext *context,
        int fds[],
        unsigned n_fds,
        char **environment,
        bool apply_permissions,
        bool apply_chroot,
        bool apply_tty_stdin,
        bool confirm_spawn,
#ifdef Use_CGroups
        CGroupControllerMask cgroup_mask,
        const char *cgroup_path,
#elif defined(Use_PTGroups)
        PTManager *ptm,
        PTGroup *ptgroup,
#endif
        const char *unit_id,
        int pipe_fd[2],
        pid_t *ret);

void exec_command_done(ExecCommand *c);
void exec_command_done_array(ExecCommand *c, unsigned n);

void exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, unsigned n);

char *exec_command_line(char **argv);

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_append_list(ExecCommand **l, ExecCommand *e);
int exec_command_set(ExecCommand *c, const char *path, ...);

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c, bool reloading_or_reexecuting);
void exec_context_tmp_dirs_done(ExecContext *c);
void exec_context_dump(ExecContext *c, FILE *f, const char *prefix);
void exec_context_tty_reset(const ExecContext *context);

int exec_context_load_environment(const ExecContext *c, char ***l);

bool exec_context_may_touch_console(ExecContext *c);
void exec_context_serialize(const ExecContext *c, Unit *u, FILE *f);

void exec_status_start(ExecStatus *s, pid_t pid);
void exec_status_exit(ExecStatus *s, ExecContext *context, pid_t pid, int code, int status);
void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix);

const char *exec_output_to_string(ExecOutput i) _const_;
ExecOutput exec_output_from_string(const char *s) _pure_;

const char *exec_input_to_string(ExecInput i) _const_;
ExecInput exec_input_from_string(const char *s) _pure_;
