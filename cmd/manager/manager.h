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

#ifndef MANAGER_H_
#define MANAGER_H_

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <dbus/dbus.h>

#include "ev.h"

#include "fdset.h"
#if defined(Use_CGroups)
#include "cgroup-util.h"
#elif defined(Use_PTGroups)
#include "ptgroup/ptgroup.h"
#endif

/* Enforce upper limit how many names we allow */
#define MANAGER_MAX_NAMES 131072 /* 128K */

typedef struct Manager Manager;

typedef enum ManagerExitCode {
        MANAGER_RUNNING,
        MANAGER_EXIT,
        MANAGER_RELOAD,
        MANAGER_REEXECUTE,
        MANAGER_REBOOT,
        MANAGER_POWEROFF,
        MANAGER_HALT,
        MANAGER_KEXEC,
        MANAGER_SWITCH_ROOT,
        _MANAGER_EXIT_CODE_MAX,
        _MANAGER_EXIT_CODE_INVALID = -1
} ManagerExitCode;

/** Additional flags for system instances. */
typedef enum SystemdSystemFlags {
	/**
         * Running as PID 1?
         *
         * If so, we have special signal disposition and carry out special tasks
         * (like mounting API filesystems).
         */
	SYSTEMD_PID1 = 1,
	/**
         * Running in a container?
         *
         * If so, and running as PID1, we skip things like setting up the clock
         * and timezone, SELinux, etc.
         *
         */
	SYSTEMD_CONTAINER = 2,
	/**
         * Running as an auxiliary service manager?
         *
         * Formally speaking, whether the D-Bus system bus is under our control.
         * If true, then the scheduler will quit if it fails to connect to the
         * system D-Bus.
         */
	SYSTEMD_AUXILIARY = 4,
} SystemdSystemFlags;

#include "unit.h"
#include "job.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "dbus/bus.h"
#include "path-lookup.h"
#include "execute.h"
#include "unit-name.h"

struct Manager {

        /* The event loop. We just make this ev_default_loop. */
        struct ev_loop *evloop;

        /* Event sources. */

        /* Note that the set of units we know of is allowed to be
         * inconsistent. However the subset of it that is loaded may
         * not, and the list of jobs may neither. */

        /* Active jobs and units */
        Hashmap *units;  /* name string => Unit object n:1 */
        Hashmap *jobs;   /* job id => Job object 1:1 */

        /* To make it easy to iterate through the units of a specific
         * type we maintain a per type linked list */
        IWLIST_HEAD(Unit, units_by_type[_UNIT_TYPE_MAX]);

        /* Units that need to be loaded */
        IWLIST_HEAD(Unit, load_queue); /* this is actually more a stack than a queue, but uh. */

        /* Jobs that need to be run */
        IWLIST_HEAD(Job, run_queue); /* more a stack than a queue, too */

        /* Units and jobs that have not yet been announced via
         * D-Bus. When something about a job changes it is added here
         * if it is not in there yet. This allows easy coalescing of
         * D-Bus change signals. */
        IWLIST_HEAD(Unit, dbus_unit_queue);
        IWLIST_HEAD(Job, dbus_job_queue);

        /* Units to remove */
        IWLIST_HEAD(Unit, cleanup_queue);

        /* Units to check when doing GC */
        IWLIST_HEAD(Unit, gc_queue);

        /* Units that should be realized */
        IWLIST_HEAD(Unit, cgroup_queue);

        /* We use two hash tables here, since the same PID might be
         * watched by two different units: once the unit that forked
         * it off, and possibly a different unit to which it was
         * joined as cgroup member. Since we know that it is either
         * one or two units for each PID we just use to hashmaps
         * here. */
        Hashmap *watch_pids1;  /* pid => Unit object n:1 */
        Hashmap *watch_pids2;  /* pid => Unit object n:1 */

        char *notify_socket;

        ev_io notify_watch;

        ev_timer jobs_in_progress_watch;
        ev_io idle_pipe_watch; /* watches idle_pipe [2] */

        unsigned n_snapshots;

        LookupPaths lookup_paths;
        Set *unit_path_cache;

        char **environment;

        usec_t runtime_watchdog;
        usec_t shutdown_watchdog;

        dual_timestamp firmware_timestamp;
        dual_timestamp loader_timestamp;
        dual_timestamp kernel_timestamp;
        dual_timestamp initrd_timestamp;
        dual_timestamp userspace_timestamp;
        dual_timestamp finish_timestamp;
        dual_timestamp generators_start_timestamp;
        dual_timestamp generators_finish_timestamp;
        dual_timestamp unitsload_start_timestamp;
        dual_timestamp unitsload_finish_timestamp;

        char *generator_unit_path;
        char *generator_unit_path_early;
        char *generator_unit_path_late;

        /* Data specific to the device subsystem */
        struct udev* udev;
        struct udev_monitor* udev_monitor;
        ev_io udev_watch;
        Hashmap *devices_by_sysfs;

        /* Data specific to the mount subsystem */
        FILE *proc_self_mountinfo;
        ev_io mount_watch;

        /* Data specific to the swap filesystem */
        FILE *proc_swaps;
        Hashmap *swaps_by_proc_swaps;
        bool request_reload;
        ev_io swap_watch;

        /* Data specific to the D-Bus subsystem */
        DBusConnection *api_bus, *system_bus;
        DBusServer *private_bus;
        Set *bus_connections, *bus_connections_for_dispatch;

        DBusMessage *queued_message; /* This is used during reloading:
                                      * before the reload we queue the
                                      * reply message here, and
                                      * afterwards we send it */
        DBusConnection *queued_message_connection; /* The connection to send the queued message on */

        Hashmap *watch_bus;  /* D-Bus names => Unit object n:1 */
        int32_t name_data_slot;
        int32_t conn_data_slot;
        int32_t subscribed_data_slot;

        bool send_reloading_done;

        uint32_t current_job_id;
        uint32_t default_unit_job_id;

        /* Data specific to the Automount subsystem */
        int dev_autofs_fd;

#ifdef Use_CGroups
        /* Data specific to the cgroup subsystem */
        Hashmap *cgroup_unit;
        CGroupControllerMask cgroup_supported;
        char *cgroup_root;
#endif

        int gc_marker;
        unsigned n_in_gc_queue;

        /* Make sure the user cannot accidentally unmount our cgroup
         * file system */
        int pin_cgroupfs_fd;


#pragma region Scheduler run state
	/** Whether the scheduler is running as System or per-User manager. */
	SystemdRunningAs running_as;

	/** If running as System manager, additional system manager flags. */
	SystemdSystemFlags system_flags;

	/**
         * If set to anything other than MANAGER_RUNNING, the main loop exits
         * and carries out the specified kind of exit.
         */
	ManagerExitCode exit_code: 5;
#pragma endregion

	bool dispatching_load_queue: 1;
	bool dispatching_run_queue: 1;
	bool dispatching_dbus_queue: 1;

	bool taint_usr: 1;

	bool show_status;
	bool confirm_spawn;
	bool no_console_output;

	ExecOutput default_std_output, default_std_error;

	usec_t default_restart_usec, default_timeout_start_usec, default_timeout_stop_usec;

	usec_t default_start_limit_interval;
	unsigned default_start_limit_burst;

	struct rlimit *rlimit[RLIM_NLIMITS];

	/* non-zero if we are reloading or reexecuting, */
	int n_reloading;

	unsigned n_installed_jobs;
	unsigned n_failed_jobs;

	/* Jobs in progress watching */
	unsigned n_running_jobs;
	unsigned n_on_console;
	unsigned jobs_in_progress_iteration;

	/* Type=idle pipes */
        int idle_pipe[4];

        char *switch_root;
        char *switch_root_init;

        /* This maps all possible path prefixes to the units needing
         * them. It's a hashmap with a path string as key and a Set as
         * value where Unit objects are contained. */
        Hashmap *units_requiring_mounts_for;

	/**
         * The runtime state base directory for this session.
         *
         * If a system instance: a copy of INSTALL_RUNSTATE_DIR.
         * If a user instance: loaded from XDG_RUNTIME_DIR if possible,
         * otherwise synthesised as INSTALL_USERSTATE_DIR/$getuid().
         *
         * e.g. /var/run
         * e.g. /var/run/user/1000
         */
	char *runtime_state_dir;

        /* $runtime_state_dir/$PKG_DIR_NAME */
        char *iw_state_dir;

#ifdef Use_KQProc
        /**
         * I/O event for the Kernel Queue on which PROC events are received.
         * (The Kernel Queue itself is in the .fd member.)
         */
        ev_io kqproc_io;
#endif

#ifdef Use_PTGroups
        /** Process Tracking Groups manager */
        PTManager *pt_manager;

        /* PTGroup object:Unit object 1:1 */
        Hashmap *ptgroup_unit;
#endif
};

int manager_new(SystemdRunningAs running_as, bool reexecuting, Manager **m);
void manager_free(Manager *m);

int manager_enumerate(Manager *m);
int manager_coldplug(Manager *m);
int manager_startup(Manager *m, FILE *serialization, FDSet *fds);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_get_unit_by_path(Manager *m, const char *path, const char *suffix, Unit **_found);

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j);

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret);
int manager_load_unit(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret);
int manager_load_unit_from_dbus_path(Manager *m, const char *s, DBusError *e, Unit **_u);

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, DBusError *e, Job **_ret);
int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool force, DBusError *e, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_clear_jobs(Manager *m);

unsigned manager_dispatch_load_queue(Manager *m);
unsigned manager_dispatch_run_queue(Manager *m);
unsigned manager_dispatch_dbus_queue(Manager *m);

int manager_environment_add(Manager *m, char **environment);
int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit);

int manager_loop(Manager *m);

void manager_dispatch_bus_name_owner_changed(Manager *m, const char *name, const char* old_owner, const char *new_owner);
void manager_dispatch_bus_query_pid_done(Manager *m, const char *name, pid_t pid);

int manager_open_serialization(Manager *m, FILE **_f);

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);
int manager_distribute_fds(Manager *m, FDSet *fds);

int manager_reload(Manager *m);

bool manager_is_reloading_or_reexecuting(Manager *m) _pure_;

void manager_reset_failed(Manager *m);

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success);
void manager_send_unit_plymouth(Manager *m, Unit *u);

bool manager_unit_inactive_or_pending(Manager *m, const char *name);

void manager_check_finished(Manager *m);

void manager_run_generators(Manager *m);
void manager_undo_generators(Manager *m);

void manager_recheck_journal(Manager *m);

void manager_set_show_status(Manager *m, bool b);
void manager_status_printf(Manager *m, bool ephemeral, const char *status, const char *format, ...) _printf_attr_(4,5);

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path);

#endif /* MANAGER_H_ */
