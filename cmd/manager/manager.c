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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "systemd/sd-daemon.h"
#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"
#include "cJSON.h"
#include "ev.h"

#include "audit-fd.h"
#include "boot-timestamps.h"
#include "bus-errors.h"
#include "dbus-job.h"
#include "dbus-unit.h"
#include "def.h"
#include "env-util.h"
#include "ev-util.h"
#include "exit-status.h"
#include "hashmap.h"
#include "locale-setup.h"
#include "log.h"
#include "macro.h"
#include "manager.h"
#include "missing.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "ratelimit.h"
#include "special.h"
#include "strv.h"
#include "transaction.h"
#include "unit-name.h"
#include "util.h"
#include "virt.h"
#include "watchdog.h"

#if defined(Use_CGroups)
#include "cgroup-util.h"
#elif defined(Use_PTGroups)
#include "ptgroup/ptgroup.h"
#endif

#ifdef Use_KQProc
#include <sys/event.h>
#include "ptgroup/kqproc.h"
#endif

#ifdef Sys_Plat_Linux
#include <linux/kd.h>
#endif

#ifdef Sys_Plat_NetBSD /* FIXME cleanup */
#define reboot(m) reboot(m, NULL)
#endif

/* As soon as 5s passed since a unit was added to our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_USEC_MAX (10*USEC_PER_SEC)

/* Initial delay and the interval for printing status messages about running jobs */
#define JOBS_IN_PROGRESS_WAIT_SEC 5
#define JOBS_IN_PROGRESS_PERIOD_SEC 1
#define JOBS_IN_PROGRESS_PERIOD_DIVISOR 3

#define TIME_T_MAX (time_t)((1UL << ((sizeof(time_t) << 3) - 1)) - 1)

static int manager_process_notify_fd(Manager *m);

static void notify_io_cb(struct ev_loop *evloop, ev_io *watch, int revents)
{
        int r;

        /* An incoming daemon notification event? */
        if (revents != EV_READ)
                return (void) log_error("Bad events on notification socket: %d\n", revents);

        if ((r = manager_process_notify_fd(watch->data)) < 0)
                return (void) log_error("Failed to process notify FD: %s\n", strerror(-r));
}

static int manager_setup_notify(Manager *m)
{
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .sa.sa_family = AF_UNIX,
        };
        int one = 1, r, fd;

        m->notify_socket = strjoin(m->iw_state_dir, "/notify", NULL);
        if (!m->notify_socket)
                return log_oom();


        ev_io_init(
                &m->notify_watch,
                notify_io_cb,
                socket(AF_UNIX, SOCK_DGRAM, 0),
                EV_READ);

        if (m->notify_watch.fd < 0) {
                log_error("Failed to allocate notification socket: %m");
                return -errno;
        }

        r = fd_cloexec(m->notify_watch.fd, true);
	r = r < 0 ? r : fd_nonblock(m->notify_watch.fd, true);

	if (r < 0) {
		log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
		close(m->notify_watch.fd);
		ev_io_zero(m->notify_watch);
		return r;
	}

        strncpy(sa.un.sun_path, m->notify_socket, sizeof(sa.un.sun_path));
        unlink(m->notify_socket);

        r = bind(m->notify_watch.fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path));
        if (r < 0) {
                log_error("bind() of %s failed: %m", sa.un.sun_path);
                return -errno;
        }

        if (m->running_as == SYSTEMD_SYSTEM) {
                r = chmod(m->notify_socket, 0777);
                if (r < 0) {
                        log_error("bind() of %s failed: %m", sa.un.sun_path);
                        return -errno;
                }
        }

        r = socket_passcred(m->notify_watch.fd);
        if (r < 0)
                return log_error_errno(-r, "SO_PASSCRED failed: %m");

        m->notify_watch.data = m;
        ev_io_start(m->evloop, &m->notify_watch);

        log_debug("Using notification socket %s", m->notify_socket);

        return 0;
}

#pragma region Jobs - in - progress and Idle
static void manager_print_jobs_in_progress(Manager *m);

static void jobs_in_progress_timer_cb(struct ev_loop *evloop, ev_timer *watch, int revents)
{
        Manager *m = watch->data;
        assert(m);
        manager_print_jobs_in_progress(m);
}

static int manager_jobs_in_progress_mod_timer(Manager *m) {
        if (m->jobs_in_progress_watch.data != m)
                return 0;

        ev_timer_again(m->evloop, &m->jobs_in_progress_watch);

        return 0;
}

static int manager_watch_jobs_in_progress(Manager *m)
{
        int r;

        if (ev_is_active(&m->jobs_in_progress_watch))
                return 0;

        ev_timer_init(
                &m->jobs_in_progress_watch,
                jobs_in_progress_timer_cb,
                JOBS_IN_PROGRESS_WAIT_SEC,
                JOBS_IN_PROGRESS_PERIOD_SEC);
        m->jobs_in_progress_watch.data = m;

        r = manager_jobs_in_progress_mod_timer(m);
        if (r < 0) {
                log_error("Failed to set up timer for jobs progress watch: %s", strerror(-r));
                goto err;
        }

        log_debug("Set up jobs progress timer.");

        return 0;

err:
        zero(m->jobs_in_progress_watch);
        return r;
}

static void manager_unwatch_jobs_in_progress(Manager *m) {
        if (!ev_is_active(&m->jobs_in_progress_watch))
                return;

        ev_timer_stop(m->evloop, &m->jobs_in_progress_watch);
        ev_timer_zero(m->jobs_in_progress_watch);
        m->jobs_in_progress_iteration = 0;

        log_debug("Closed jobs progress timer.");
}

#define CYLON_BUFFER_EXTRA (2*strlen(ANSI_RED_ON) + strlen(ANSI_HIGHLIGHT_RED_ON) + 2*strlen(ANSI_HIGHLIGHT_OFF))
static void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos) {
        char *p = buffer;

        assert(buflen >= CYLON_BUFFER_EXTRA + width + 1);
        assert(pos <= width+1); /* 0 or width+1 mean that the center light is behind the corner */

        if (pos > 1) {
                if (pos > 2)
                        p = mempset(p, ' ', pos-2);
                p = stpcpy(p, ANSI_RED_ON);
                *p++ = '*';
        }

        if (pos > 0 && pos <= width) {
                p = stpcpy(p, ANSI_HIGHLIGHT_RED_ON);
                *p++ = '*';
        }

        p = stpcpy(p, ANSI_HIGHLIGHT_OFF);

        if (pos < width) {
                p = stpcpy(p, ANSI_RED_ON);
                *p++ = '*';
                if (pos < width-1)
                        p = mempset(p, ' ', width-1-pos);
                p = stpcpy(p, ANSI_HIGHLIGHT_OFF);
        }
}

static void manager_print_jobs_in_progress(Manager *m) {
        Iterator i;
        Job *j;
        char *job_of_n = NULL;
        unsigned counter = 0, print_nr;
        char cylon[6 + CYLON_BUFFER_EXTRA + 1];
        unsigned cylon_pos;
        char time[FORMAT_TIMESPAN_MAX], limit[FORMAT_TIMESPAN_MAX] = "no limit";
        usec_t x;

        print_nr = (m->jobs_in_progress_iteration / JOBS_IN_PROGRESS_PERIOD_DIVISOR) % m->n_running_jobs;

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->state == JOB_RUNNING && counter++ == print_nr)
                        break;

        /* m->n_running_jobs must be consistent with the contents of m->jobs,
         * so the above loop must have succeeded in finding j. */
        assert(counter == print_nr + 1);

        cylon_pos = m->jobs_in_progress_iteration % 14;
        if (cylon_pos >= 8)
                cylon_pos = 14 - cylon_pos;
        draw_cylon(cylon, sizeof(cylon), 6, cylon_pos);

        m->jobs_in_progress_iteration++;

        if (m->n_running_jobs > 1)
                if (asprintf(&job_of_n, "(%u of %u) ", counter, m->n_running_jobs) < 0)
                        job_of_n = NULL;

        format_timespan(time, sizeof(time),
                ev_tstamp_to_usec(ev_now(m->evloop)) - j->begin_usec, 1*USEC_PER_SEC);
        if (job_get_timeout(j, &x) > 0)
                format_timespan(limit, sizeof(limit), x - j->begin_usec, 1*USEC_PER_SEC);

        manager_status_printf(m, true, cylon,
                              "%sA %s job is running for %s (%s / %s)",
                              strempty(job_of_n),
                              job_type_to_string(j->type),
                              unit_description(j->unit),
                              time, limit);
        free(job_of_n);

}

static void manager_unwatch_idle_pipe(Manager *m);
static void close_idle_pipe(Manager *m);

static void idle_pipe_io_cb(struct ev_loop *evloop, ev_io *ev, int revents)
{
        Manager *m = ev->data;

        assert(revents & EV_READ);

        m->no_console_output = m->n_on_console > 0;
        manager_unwatch_idle_pipe(m);
        close_idle_pipe(m);
}

static int manager_watch_idle_pipe(Manager *m)
{
        int r;

        if (ev_is_active(&m->idle_pipe_watch))
                return 0;

        if (m->idle_pipe_watch.fd < 0)
                return 0;

        if (m->idle_pipe[2] < 0)
                return 0;

        ev_io_init(&m->idle_pipe_watch, idle_pipe_io_cb, m->idle_pipe[2], EV_READ);
        m->idle_pipe_watch.data = m;
        ev_io_start(m->evloop, &m->idle_pipe_watch);
        log_debug("Set up idle_pipe watch.");

        return 0;

err:
        safe_close(m->idle_pipe_watch.fd);
        m->idle_pipe_watch.fd = -1;
        return r;
}

static void manager_unwatch_idle_pipe(Manager *m) {
        if (m->idle_pipe_watch.fd < 0)
                return;

        ev_io_stop(m->evloop, &m->idle_pipe_watch);
        m->idle_pipe_watch.fd = -1;

        log_debug("Closed idle_pipe watch.");
}

static void close_idle_pipe(Manager *m)
{
        close_pipe(m->idle_pipe);
        close_pipe(m->idle_pipe + 2);
}
#pragma endregion


static int enable_special_signals(Manager *m) {
        int fd;

        assert(m);

#ifdef RB_DISABLE_CAD
        /* Enable that we get SIGINT on control-alt-del. In containers
         * this will fail with EPERM (older) or EINVAL (newer), so
         * ignore that. */
        if (reboot(RB_DISABLE_CAD) < 0 && errno != EPERM && errno != EINVAL)
#endif
                log_warning("Failed to enable ctrl-alt-del handling: %m");

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                /* Support systems without virtual console */
                if (fd != -ENOENT)
                        log_warning("Failed to open /dev/tty0: %m");
        } else {
#ifdef KDSIGACCEPT
                /* Enable that we get SIGWINCH on kbrequest */
                if (ioctl(fd, KDSIGACCEPT, SIGWINCH) < 0)
#endif
                        log_warning("Failed to enable kbrequest handling: %s", strerror(errno));

                safe_close(fd);
        }

        return 0;
}

static void manager_signal_cb(struct ev_loop *evloop, ev_signal *watch, int revents);
static void manager_sigrt_signal_cb(struct ev_loop *evloop, ev_signal *watch, int revents);


static int manager_setup_signals(Manager *m) {
        sigset_t mask;
        struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_NOCLDSTOP|SA_RESTART,
        };
        int signals[] = {
                SIGCHLD, /* Child died */
                SIGTERM, /* Reexecute daemon */
                SIGHUP,  /* Reload configuration */
                SIGUSR1, /* systemd/upstart: reconnect to D-Bus */
                SIGUSR2, /* systemd: dump status */
#ifndef DEBUG
                SIGINT, /* Kernel sends us this on control-alt-del */
#endif
                SIGWINCH, /* Kernel sends us this on kbrequest (alt-arrowup) */
#ifdef SIGPWR
                SIGPWR, /* Some kernel drivers and upsd send us this on power failure */
#endif
#ifdef SIGRTMIN
                SIGRTMIN + 0,  /* systemd: start default.target */
                SIGRTMIN + 1,  /* systemd: isolate rescue.target */
                SIGRTMIN + 2,  /* systemd: isolate emergency.target */
                SIGRTMIN + 3,  /* systemd: start halt.target */
                SIGRTMIN + 4,  /* systemd: start poweroff.target */
                SIGRTMIN + 5,  /* systemd: start reboot.target */
                SIGRTMIN + 6,  /* systemd: start kexec.target */
                SIGRTMIN + 13, /* systemd: Immediate halt */
                SIGRTMIN + 14, /* systemd: Immediate poweroff */
                SIGRTMIN + 15, /* systemd: Immediate reboot */
                SIGRTMIN + 16, /* systemd: Immediate kexec */
                SIGRTMIN + 20, /* systemd: enable status messages */
                SIGRTMIN + 21, /* systemd: disable status messages */
                SIGRTMIN + 22, /* systemd: set log level to LOG_DEBUG */
                SIGRTMIN + 23, /* systemd: set log level to LOG_INFO */
                SIGRTMIN + 24, /* systemd: Immediate exit (--user only) */
                SIGRTMIN + 26, /* systemd: set log target to journal-or-kmsg */
                SIGRTMIN + 27, /* systemd: set log target to console */
                SIGRTMIN + 28, /* systemd: set log target to kmsg */
                SIGRTMIN + 29, /* systemd: set log target to syslog-or-kmsg */
#endif
        };
        static ev_signal ev_signals[255] = {};

        assert(m);

        /* We are not interested in SIGSTOP and friends. */
        assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

        assert_se(sigemptyset(&mask) == 0);

        for (int i = 0; i < ELEMENTSOF(signals); i++) {
                ev_signal_init(
                        &ev_signals[i],
#ifdef SIGRTMIN
                        signals[i] >= SIGRTMIN ? manager_sigrt_signal_cb :
#endif
                        manager_signal_cb,
                        signals[i]);
                ev_signals[i].data = m;
                assert_se(sigaddset(&mask, signals[i]) == 0);
                ev_signal_start(m->evloop, &ev_signals[i]);
        }

	// assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0); // FIXME: ??

	if (m->running_as == SYSTEMD_SYSTEM)
                return enable_special_signals(m);

        return 0;
}

static int manager_default_environment(Manager *m) {
        assert(m);

        if (m->running_as == SYSTEMD_SYSTEM) {
                /* The system manager always starts with a clean
                 * environment for its children. It does not import
                 * the kernel or the parents exported variables.
                 *
                 * The initial passed environ is untouched to keep
                 * /proc/self/environ valid; it is used for tagging
                 * the init process inside containers. */
                m->environment = strv_new("PATH=" DEFAULT_PATH,
                                          NULL);

                /* Import locale variables LC_*= from configuration */
                locale_setup(&m->environment);
        } else
                /* The user manager passes its own environment
                 * along to its children. */
                m->environment = strv_copy(environ);

        if (!m->environment)
                return -ENOMEM;

        return 0;
}

int manager_new(SystemdRunningAs running_as, bool reexecuting, Manager **_m) {
        Manager *m;
        int r = -ENOMEM;

        assert(_m);
        assert(running_as >= 0);
        assert(running_as < _SYSTEMD_RUNNING_AS_MAX);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        /* initialise libev event loop */
        m->evloop = ev_default_loop(EVFLAG_NOSIGMASK);
        if (!m->evloop) {
                log_error("Failed to create event loop: %s", strerror(r));
                goto fail;
        }

#ifdef ENABLE_EFI
        if (running_as == SYSTEMD_SYSTEM && detect_container(NULL) <= 0)
                boot_timestamps(&m->userspace_timestamp, &m->firmware_timestamp, &m->loader_timestamp);
#endif

        m->running_as = running_as;
        m->name_data_slot = m->conn_data_slot = m->subscribed_data_slot = -1;
        m->exit_code = _MANAGER_EXIT_CODE_INVALID;
        m->pin_cgroupfs_fd = -1;
        m->idle_pipe[0] = m->idle_pipe[1] = m->idle_pipe[2] = m->idle_pipe[3] = -1;

        ev_io_zero(m->mount_watch);
        ev_io_zero(m->swap_watch);
        ev_io_zero(m->udev_watch);
        ev_timer_zero(m->jobs_in_progress_watch);

        m->dev_autofs_fd = -1;
        m->current_job_id = 1; /* start as id #1, so that we can leave #0 around as "null-like" value */

        if (running_as == SYSTEMD_SYSTEM) {
		m->runtime_state_dir = strdup(INSTALL_RUNSTATE_DIR);
		if (!m->runtime_state_dir) {
			r = ENOMEM;
			goto fail;
		}

	} else {
		const char *e = getenv("XDG_RUNTIME_DIR");
		if (!e) {
			r = asprintf(&m->runtime_state_dir, INSTALL_USERSTATE_DIR "/%llu",
			    (long long unsigned) getuid());
			if (r < 0)
				goto fail;


			r = mkdir(m->runtime_state_dir, 0700);
			if (r < 0 && !(errno == EEXIST && is_dir(m->runtime_state_dir))) {
				log_error("Failed to create user's runtime state directory %s: %s",
				    m->runtime_state_dir, strerror(-r));
				goto fail;
			}

			setenv("XDG_RUNTIME_DIR", m->runtime_state_dir, 0);
		} else
			m->runtime_state_dir = strdup(e);
	}

	m->iw_state_dir = strjoin(m->runtime_state_dir, "/" PACKAGE_NAME, NULL);
	if (!m->iw_state_dir) {
                r = ENOMEM;
                goto fail;
        }

        r = mkdir(m->iw_state_dir, running_as == SYSTEMD_SYSTEM ? 0755 : 0700);
        if (r < 0 && !(errno == EEXIST && is_dir(m->iw_state_dir))) {
                log_error(
                        "Failed to create InitWare runtime state directory %s: %s",
                        m->iw_state_dir,
                        strerror(-r));
                goto fail;
        }

        r = manager_default_environment(m);
        if (r < 0)
                goto fail;

        if (!(m->units = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->watch_pids1 = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->watch_pids2 = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

#if defined(Use_CGroups)
	m->cgroup_unit = hashmap_new(string_hash_func, string_compare_func);
        if (!m->cgroup_unit)
                goto fail;
#elif defined(Use_PTGroups)
	m->ptgroup_unit = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!m->ptgroup_unit)
                goto fail;
#endif

        m->watch_bus = hashmap_new(string_hash_func, string_compare_func);
        if (!m->watch_bus)
                goto fail;

        r = manager_setup_signals(m);
        if (r < 0)
                goto fail;

#ifdef Use_CGroups
        r = manager_setup_cgroup(m);
        if (r < 0)
                goto fail;
#endif

#ifdef Use_KQProc
        if (!reexecuting) {
                r = manager_setup_kqproc_watch(m, -1);
                if (r < 0)
                        goto fail;
        }
#endif

#ifdef Use_PTGroups
        if (!reexecuting) {
                m->pt_manager = ptmanager_new(m, strdup(running_as == SYSTEMD_SYSTEM ? "sys:" : "usr:"));
                if (!m->pt_manager) {
                        log_error("Failed to allocate root PT group\n");
                        r = -ENOMEM;
                }
        }
#endif

        r = manager_setup_notify(m);
        if (r < 0)
                goto fail;

        /* Try to connect to the busses, if possible. */
        if ((running_as == SYSTEMD_USER && getenv("DBUS_SESSION_BUS_ADDRESS")) ||
            running_as == SYSTEMD_SYSTEM) {
                r = bus_init(m, reexecuting || running_as != SYSTEMD_SYSTEM);
                if (r < 0)
                        goto fail;
        } else
                log_debug("Skipping DBus session bus connection attempt - no DBUS_SESSION_BUS_ADDRESS set...");

        m->taint_usr = dir_is_empty("/usr") > 0;

        *_m = m;
        return 0;

fail:
        manager_free(m);
        return r;
}

static unsigned manager_dispatch_cleanup_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        while ((u = m->cleanup_queue)) {
                assert(u->in_cleanup_queue);

                unit_free(u);
                n++;
        }

        return n;
}

enum {
        GC_OFFSET_IN_PATH,  /* This one is on the path we were traveling */
        GC_OFFSET_UNSURE,   /* No clue */
        GC_OFFSET_GOOD,     /* We still need this unit */
        GC_OFFSET_BAD,      /* We don't need this unit anymore */
        _GC_OFFSET_MAX
};

static void unit_gc_sweep(Unit *u, unsigned gc_marker) {
        Iterator i;
        Unit *other;
        bool is_bad;

        assert(u);

        if (u->gc_marker == gc_marker + GC_OFFSET_GOOD ||
            u->gc_marker == gc_marker + GC_OFFSET_BAD ||
            u->gc_marker == gc_marker + GC_OFFSET_IN_PATH)
                return;

        if (u->in_cleanup_queue)
                goto bad;

        if (unit_check_gc(u))
                goto good;

        u->gc_marker = gc_marker + GC_OFFSET_IN_PATH;

        is_bad = true;

        SET_FOREACH(other, u->dependencies[UNIT_REFERENCED_BY], i) {
                unit_gc_sweep(other, gc_marker);

                if (other->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        if (is_bad)
                goto bad;

        /* We were unable to find anything out about this entry, so
         * let's investigate it later */
        u->gc_marker = gc_marker + GC_OFFSET_UNSURE;
        unit_add_to_gc_queue(u);
        return;

bad:
        /* We definitely know that this one is not useful anymore, so
         * let's mark it for deletion */
        u->gc_marker = gc_marker + GC_OFFSET_BAD;
        unit_add_to_cleanup_queue(u);
        return;

good:
        u->gc_marker = gc_marker + GC_OFFSET_GOOD;
}

static unsigned manager_dispatch_gc_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;
        unsigned gc_marker;

        assert(m);

        /* log_debug("Running GC..."); */

        m->gc_marker += _GC_OFFSET_MAX;
        if (m->gc_marker + _GC_OFFSET_MAX <= _GC_OFFSET_MAX)
                m->gc_marker = 1;

        gc_marker = m->gc_marker;

        while ((u = m->gc_queue)) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

                IWLIST_REMOVE(Unit, gc_queue, m->gc_queue, u);
                u->in_gc_queue = false;

                n++;

                if (u->gc_marker == gc_marker + GC_OFFSET_BAD ||
                    u->gc_marker == gc_marker + GC_OFFSET_UNSURE) {
                        log_debug_unit(u->id, "Collecting %s", u->id);
                        u->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(u);
                }
        }

        m->n_in_gc_queue = 0;

        return n;
}

static void manager_clear_jobs_and_units(Manager *m) {
        Unit *u;

        assert(m);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        manager_dispatch_cleanup_queue(m);

        assert(!m->load_queue);
        assert(!m->run_queue);
        assert(!m->dbus_unit_queue);
        assert(!m->dbus_job_queue);
        assert(!m->cleanup_queue);
        assert(!m->gc_queue);

        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));

        m->n_on_console = 0;
        m->n_running_jobs = 0;
}

void manager_free(Manager *m)
{
        UnitType c;
        int i;

        assert(m);

        manager_clear_jobs_and_units(m);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

#ifdef Sys_Plat_Linux
        /* If we reexecute ourselves, we keep the root cgroup
         * around */
        manager_shutdown_cgroup(m, m->exit_code != MANAGER_REEXECUTE);
#endif

        manager_undo_generators(m);

        bus_done(m);

        hashmap_free(m->units);
        hashmap_free(m->jobs);
        hashmap_free(m->watch_pids1);
        hashmap_free(m->watch_pids2);
        hashmap_free(m->watch_bus);

        safe_close(m->notify_watch.fd);
        manager_unwatch_jobs_in_progress(m);

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->environment);

#if defined(Use_CGroups)
	hashmap_free(m->cgroup_unit);
#elif defined(Use_PTGroups)
	hashmap_free(m->ptgroup_unit);
#endif

        set_free_free(m->unit_path_cache);

        manager_unwatch_idle_pipe(m);
        close_idle_pipe(m);

        ev_default_destroy();

        free(m->switch_root);
        free(m->switch_root_init);

        for (i = 0; i < RLIM_NLIMITS; i++)
                free(m->rlimit[i]);

        assert(hashmap_isempty(m->units_requiring_mounts_for));
        hashmap_free(m->units_requiring_mounts_for);

        free(m->runtime_state_dir);
        free(m->iw_state_dir);

        free(m);
}

int manager_enumerate(Manager *m) {
        int r = 0, q;
        UnitType c;

        assert(m);

        /* Let's ask every type to load all units from disk/kernel
         * that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->enumerate) {
                        q = unit_vtable[c]->enumerate(m);
                        if (q < 0)
                                r = q;
                }

        manager_dispatch_load_queue(m);
        return r;
}

int manager_coldplug(Manager *m) {
        int r = 0, q;
        Iterator i;
        Unit *u;
        char *k;

        assert(m);

        /* Then, let's set up their initial state. */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                if ((q = unit_coldplug(u)) < 0)
                        r = q;
        }

        return r;
}

static void manager_build_unit_path_cache(Manager *m) {
        char **i;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        set_free_free(m->unit_path_cache);

        m->unit_path_cache = set_new(string_hash_func, string_compare_func);
        if (!m->unit_path_cache) {
                log_error("Failed to allocate unit path cache.");
                return;
        }

        /* This simply builds a list of files we know exist, so that
         * we don't always have to go to disk */

        STRV_FOREACH(i, m->lookup_paths.unit_path) {
                struct dirent *de;

                d = opendir(*i);
                if (!d) {
                        if (errno != ENOENT)
                                log_error("Failed to open directory %s: %m", *i);
                        continue;
                }

                while ((de = readdir(d))) {
                        char *p;

                        if (ignore_file(de->d_name))
                                continue;

                        p = strjoin(streq(*i, "/") ? "" : *i, "/", de->d_name, NULL);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        r = set_consume(m->unit_path_cache, p);
                        if (r < 0)
                                goto fail;
                }

                closedir(d);
                d = NULL;
        }

        return;

fail:
        log_error("Failed to build unit path cache: %s", strerror(-r));

        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r, q;

        assert(m);

        dual_timestamp_get(&m->generators_start_timestamp);
        manager_run_generators(m);
        dual_timestamp_get(&m->generators_finish_timestamp);

        r = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
                        NULL,
                        m->generator_unit_path,
                        m->generator_unit_path_early,
                        m->generator_unit_path_late);
        if (r < 0)
                return r;

        manager_build_unit_path_cache(m);

        /* If we will deserialize make sure that during enumeration
         * this is already known, so we increase the counter here
         * already */
        if (serialization)
                m->n_reloading ++;

        /* First, enumerate what we can from all config files */
        dual_timestamp_get(&m->unitsload_start_timestamp);
        r = manager_enumerate(m);
        dual_timestamp_get(&m->unitsload_finish_timestamp);

        /* Second, deserialize if there is something to deserialize */
        if (serialization) {
                q = manager_deserialize(m, serialization, fds);
                if (q < 0)
                        r = q;
        }

        /* Any fds left? Find some unit which wants them. This is
         * useful to allow container managers to pass some file
         * descriptors to us pre-initialized. This enables
         * socket-based activation of entire containers. */
        if (fdset_size(fds) > 0) {
                q = manager_distribute_fds(m, fds);
                if (q < 0)
                        r = q;
        }

        /* Third, fire things up! */
        q = manager_coldplug(m);
        if (q < 0)
                r = q;

        if (serialization) {
                assert(m->n_reloading > 0);
                m->n_reloading --;

                /* Let's wait for the UnitNew/JobNew messages being
                 * sent, before we notify that the reload is
                 * finished */
                m->send_reloading_done = true;
        }

        return r;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool override, DBusError *e, Job **_ret) {
        int r;
        Transaction *tr;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START) {
                dbus_set_error(e, BUS_ERROR_INVALID_JOB_MODE, "Isolate is only valid for start.");
                return -EINVAL;
        }

        if (mode == JOB_ISOLATE && !unit->allow_isolate) {
                dbus_set_error(e, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");
                return -EPERM;
        }

        log_debug_unit(unit->id,
                       "Trying to enqueue job %s/%s/%s", unit->id,
                       job_type_to_string(type), job_mode_to_string(mode));

        job_type_collapse(&type, unit);

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        r = transaction_add_job_and_dependencies(tr, type, unit, NULL, true, override, false,
                                                 mode == JOB_IGNORE_DEPENDENCIES || mode == JOB_IGNORE_REQUIREMENTS,
                                                 mode == JOB_IGNORE_DEPENDENCIES, e);
        if (r < 0)
                goto tr_abort;

        if (mode == JOB_ISOLATE) {
                r = transaction_add_isolate_jobs(tr, m);
                if (r < 0)
                        goto tr_abort;
        }

        r = transaction_activate(tr, m, mode, e);
        if (r < 0)
                goto tr_abort;

        log_debug_unit(unit->id,
                       "Enqueued job %s/%s as %u", unit->id,
                       job_type_to_string(type), (unsigned) tr->anchor_job->id);

        if (_ret)
                *_ret = tr->anchor_job;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool override, DBusError *e, Job **_ret) {
        Unit *unit;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_load_unit(m, name, NULL, NULL, &unit);
        if (r < 0)
                return r;

        return manager_add_job(m, type, unit, mode, override, e, _ret);
}

Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Unit *manager_get_unit(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->units, name);
}

unsigned manager_dispatch_load_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a unit from the queue and
         * tries to load its data until the queue is empty */

        while ((u = m->load_queue)) {
                assert(u->in_load_queue);

                unit_load(u);
                n++;
        }

        m->dispatching_load_queue = false;
        return n;
}

int manager_load_unit_prepare(
                Manager *m,
                const char *name,
                const char *path,
                DBusError *e,
                Unit **_ret) {

        Unit *ret;
        UnitType t;
        int r;

        assert(m);
        assert(name || path);

        /* This will prepare the unit for loading, but not actually
         * load anything from disk. */

        if (path && !is_path(path)) {
                dbus_set_error(e, BUS_ERROR_INVALID_PATH, "Path %s is not absolute.", path);
                return -EINVAL;
        }

        if (!name)
                name = path_get_file_name(path);

        t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, false)) {
                dbus_set_error(e, BUS_ERROR_INVALID_NAME, "Unit name %s is not valid.", name);
                return -EINVAL;
        }

        ret = manager_get_unit(m, name);
        if (ret) {
                *_ret = ret;
                return 1;
        }

        ret = unit_new(m, unit_vtable[t]->object_size);
        if (!ret)
                return -ENOMEM;

        if (path) {
                ret->fragment_path = strdup(path);
                if (!ret->fragment_path) {
                        unit_free(ret);
                        return -ENOMEM;
                }
        }

        r = unit_add_name(ret, name);
        if (r < 0) {
                unit_free(ret);
                return r;
        }

        unit_add_to_load_queue(ret);
        unit_add_to_dbus_queue(ret);
        unit_add_to_gc_queue(ret);

        if (_ret)
                *_ret = ret;

        return 0;
}

int manager_load_unit(
                Manager *m,
                const char *name,
                const char *path,
                DBusError *e,
                Unit **_ret) {

        int r;

        assert(m);

        /* This will load the service information files, but not actually
         * start any services or anything. */

        r = manager_load_unit_prepare(m, name, path, e, _ret);
	if (r != 0)
		return r;

	manager_dispatch_load_queue(m);

        if (_ret)
                *_ret = unit_follow_merge(*_ret);

        return 0;
}

void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Job *j;

        assert(s);
        assert(f);

        HASHMAP_FOREACH(j, s->jobs, i)
                job_dump(j, f, prefix);
}

void manager_dump_units(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Unit *u;
        const char *t;

        assert(s);
        assert(f);

        HASHMAP_FOREACH_KEY(u, t, s->units, i)
                if (u->id == t)
                        unit_dump(u, f, prefix);
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->jobs)))
                /* No need to recurse. We're cancelling all jobs. */
                job_finish_and_invalidate(j, JOB_CANCELED, false);
}

unsigned manager_dispatch_run_queue(Manager *m) {
        Job *j;
        unsigned n = 0;

        if (m->dispatching_run_queue)
                return 0;

        m->dispatching_run_queue = true;

        while ((j = m->run_queue)) {
                assert(j->installed);
                assert(j->in_run_queue);

                job_run_and_invalidate(j);
                n++;
        }

        m->dispatching_run_queue = false;

        if (m->n_running_jobs > 0)
                manager_watch_jobs_in_progress(m);

        if (m->n_on_console > 0)
                manager_watch_idle_pipe(m);

        return n;
}

unsigned manager_dispatch_dbus_queue(Manager *m) {
        Job *j;
        Unit *u;
        unsigned n = 0;

        assert(m);

        if (m->dispatching_dbus_queue)
                return 0;

        m->dispatching_dbus_queue = true;

        while ((u = m->dbus_unit_queue)) {
                assert(u->in_dbus_queue);

                bus_unit_send_change_signal(u);
                n++;
        }

        while ((j = m->dbus_job_queue)) {
                assert(j->in_dbus_queue);

                bus_job_send_change_signal(j);
                n++;
        }

        m->dispatching_dbus_queue = false;

        if (m->send_reloading_done) {
                m->send_reloading_done = false;

                bus_broadcast_reloading(m, false);
        }

        return n;
}

static void manager_invoke_notify_message(Manager *m, Unit *u, pid_t pid, char *buf, size_t n) {
        _cleanup_strv_free_ char **tags = NULL;

        assert(m);
        assert(u);
        assert(buf);
        assert(n > 0);

        tags = strv_split(buf, "\n\r");
        if (!tags) {
                log_oom();
                return;
        }

        log_debug_unit(u->id, "Got notification message for unit %s", u->id);

        if (UNIT_VTABLE(u)->notify_message)
                UNIT_VTABLE(u)->notify_message(u, pid, tags);
}

static int manager_process_notify_fd(Manager *m) {
        ssize_t n;

        assert(m);

        for (;;) {
                char buf[4096];
                struct iovec iovec = {
                        .iov_base = buf,
                        .iov_len = sizeof(buf)-1,
                };

                bool found = false;

                union {
                        struct cmsghdr cmsghdr;
#ifdef CMSG_CREDS_STRUCT
			uint8_t buf[CMSG_SPACE(CMSG_CREDS_STRUCT_SIZE)];
#endif
                } control = {};

                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };
                struct socket_ucred ucred;
                Unit *u;

                n = recvmsg(m->notify_watch.fd, &msghdr, MSG_DONTWAIT);
                if (n <= 0) {
                        if (n == 0)
                                return -EIO;

                        if (errno == EAGAIN || errno == EINTR)
                                break;

                        return -errno;
                }

#ifdef CMSG_CREDS_STRUCT
		n = cmsg_readucred(&control.cmsghdr, &ucred);
		if (!n) {
			log_warning("Received notify message without credentials - refusing.\n");
                        return 0;
		}

		u = manager_get_unit_by_pid(m, ucred.pid);
                if (u) {
                        manager_invoke_notify_message(m, u, ucred.pid, buf, n);
                        found = true;
                }

                u = hashmap_get(m->watch_pids1, LONG_TO_PTR(ucred.pid));
                if (u) {
                        manager_invoke_notify_message(m, u, ucred.pid, buf, n);
                        found = true;
                }

                u = hashmap_get(m->watch_pids2, LONG_TO_PTR(ucred.pid));
                if (u) {
                        manager_invoke_notify_message(m, u, ucred.pid, buf, n);
                        found = true;
                }

                if (!found)
                        log_warning(
                                "Cannot find unit for notify message of PID %lu.", (long unsigned) ucred.pid);
#else
                log_warning("Notify messages are not implemented on this platform\n");
#endif
        }

        return 0;
}

static void invoke_sigchld_event(Manager *m, Unit *u, siginfo_t *si) {
        assert(m);
        assert(u);
        assert(si);

        log_debug_unit(u->id, "Child %lu belongs to %s",(long unsigned) si->si_pid, u->id);

        unit_unwatch_pid(u, si->si_pid);
        UNIT_VTABLE(u)->sigchld_event(u, si->si_pid, si->si_code, si->si_status);
}

static int manager_dispatch_sigchld(Manager *m) {
    assert(m);

    for (;;) {
            siginfo_t si = {};

#ifndef Have_waitid
            if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG) < 0) {
#else
            /* First we call waitd() for a PID and do not reap the
             * zombie. That way we can still access /proc/$PID for
             * it while it is a zombie. */
            if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG|WNOWAIT) < 0) {
#endif

                    if (errno == ECHILD)
                            break;

                    if (errno == EINTR)
                            continue;

                    return -errno;
            }

	    if (si.si_pid <= 0)
                    break;

            if (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED) {
                    _cleanup_free_ char *name = NULL;
                    Unit *u;

#ifdef Have_waitid
                    get_process_comm(si.si_pid, &name);
#endif

                    log_debug("Child %lu (%s) died (code=%s, status=%i/%s)",
                              (long unsigned) si.si_pid, strna(name),
                              sigchld_code_to_string(si.si_code),
                              si.si_status,
                              strna(si.si_code == CLD_EXITED
                                    ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)
                                    : signal_to_string(si.si_status)));

#if defined(Use_CGroups) || defined(Use_KQProc)
                    /* And now figure out the unit this belongs
                     * to, it might be multiple... */
                    u = manager_get_unit_by_pid(m, si.si_pid);
                    if (u)
                            invoke_sigchld_event(m, u, &si);
#endif
                    u = hashmap_get(m->watch_pids1, LONG_TO_PTR(si.si_pid));
                    if (u)
                            invoke_sigchld_event(m, u, &si);
                    u = hashmap_get(m->watch_pids2, LONG_TO_PTR(si.si_pid));
                    if (u)
                            invoke_sigchld_event(m, u, &si);
            }

#ifdef Have_waitid
            /* And now, we actually reap the zombie. */
            if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                    if (errno == EINTR)
                            continue;

                    return -errno;
            }
#endif
    }

    return 0;
}

static int manager_start_target(Manager *m, const char *name, JobMode mode) {
        int r;
        DBusError error;

        dbus_error_init(&error);

        log_debug_unit(name, "Activating special unit %s", name);

        r = manager_add_job_by_name(m, JOB_START, name, mode, true, &error, NULL);
        if (r < 0)
                log_error_unit(name,
                               "Failed to enqueue %s job: %s", name, bus_error(&error, r));

        dbus_error_free(&error);

        return r;
}

static void manager_sigrt_signal_cb(struct ev_loop *evloop, ev_signal *watch, int revents)
{
        /* Starting SIGRTMIN+0 */
        static const char *const target_table[] = {
                [0] = SPECIAL_DEFAULT_TARGET,   [1] = SPECIAL_RESCUE_TARGET,
                [2] = SPECIAL_EMERGENCY_TARGET, [3] = SPECIAL_HALT_TARGET,
                [4] = SPECIAL_POWEROFF_TARGET,  [5] = SPECIAL_REBOOT_TARGET,
                [6] = SPECIAL_KEXEC_TARGET
        };

        /* Starting SIGRTMIN+13, so that target halt and system halt are 10 apart */
        static const ManagerExitCode code_table[] = {
                [0] = MANAGER_HALT, [1] = MANAGER_POWEROFF, [2] = MANAGER_REBOOT, [3] = MANAGER_KEXEC
        };

        Manager *m = watch->data;

#ifdef SIGRTMIN
        if ((int) watch->signum >= SIGRTMIN + 0 &&
            (int) watch->signum < SIGRTMIN + (int) ELEMENTSOF(target_table)) {
                int idx = (int) watch->signum - SIGRTMIN;
                manager_start_target(
                        m, target_table[idx], (idx == 1 || idx == 2) ? JOB_ISOLATE : JOB_REPLACE);
                return;
        }

        if ((int) watch->signum >= SIGRTMIN + 13 &&
            (int) watch->signum < SIGRTMIN + 13 + (int) ELEMENTSOF(code_table)) {
                m->exit_code = code_table[watch->signum - SIGRTMIN - 13];
                return;
        }

        switch (watch->signum - SIGRTMIN) {

        case 20:
                log_debug("Enabling showing of status.");
                manager_set_show_status(m, true);
                break;

        case 21:
                log_debug("Disabling showing of status.");
                manager_set_show_status(m, false);
                break;

        case 22:
                log_set_max_level(LOG_DEBUG);
                log_notice("Setting log level to debug.");
                break;

        case 23:
                log_set_max_level(LOG_INFO);
                log_notice("Setting log level to info.");
                break;

        case 24:
#if 0
                                if (m->running_as == SYSTEMD_USER) {
#endif
                m->exit_code = MANAGER_EXIT;
                return;

#if 0
                                }

                                /* This is a nop on init */
#endif /* no it isn't */
                break;

        case 26:
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_notice("Setting log target to journal-or-kmsg.");
                break;

        case 27:
                log_set_target(LOG_TARGET_CONSOLE);
                log_notice("Setting log target to console.");
                break;

        case 28:
                log_set_target(LOG_TARGET_KMSG);
                log_notice("Setting log target to kmsg.");
                break;

        case 29:
                log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
                log_notice("Setting log target to syslog-or-kmsg.");
                break;

        default:
                log_warning("Unhandled signal %s", signal_to_string(watch->signum));
        }
#endif /* SIGRTMIN */
}

static void manager_signal_cb(struct ev_loop *evloop, ev_signal *watch, int revents)
{
        Manager *m = watch->data;
        ssize_t n;
        bool sigchld = false;

        assert(m);

        log_full(
                watch->signum == SIGCHLD || (watch->signum == SIGTERM && m->running_as == SYSTEMD_USER) ?
                        LOG_DEBUG :
                        LOG_INFO,
                "Received SIG%s.",
                signal_to_string(watch->signum));

        switch (watch->signum) {

        case SIGCHLD:
                sigchld = true;
                break;

        case SIGTERM:
                if (m->running_as == SYSTEMD_SYSTEM) {
                        /* This is for compatibility with the
                         * original sysvinit */
                        m->exit_code = MANAGER_REEXECUTE;
                        break;
                }

                /* Fall through */

        case SIGINT:
                if (m->running_as == SYSTEMD_SYSTEM) {
                        manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE_IRREVERSIBLY);
                        break;
                }

                /* Run the exit target if there is one, if not, just exit. */
                if (manager_start_target(m, SPECIAL_EXIT_TARGET, JOB_REPLACE) < 0) {
                        m->exit_code = MANAGER_EXIT;
                        return;
                }

                break;

        case SIGWINCH:
                if (m->running_as == SYSTEMD_SYSTEM)
                        manager_start_target(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                /* This is a nop on non-init */
                break;

#ifdef SIGPWR
        case SIGPWR:
                if (m->running_as == SYSTEMD_SYSTEM)
                        manager_start_target(m, SPECIAL_SIGPWR_TARGET, JOB_REPLACE);

                /* This is a nop on non-init */
                break;
#endif

        case SIGUSR1: {
                Unit *u;

                u = manager_get_unit(m, SPECIAL_DBUS_SERVICE);

                if (!u || UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u))) {
                        log_info("Trying to reconnect to bus...");
                        bus_init(m, true);
                }

                if (!u || !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u))) {
                        log_info("Loading D-Bus service...");
                        manager_start_target(m, SPECIAL_DBUS_SERVICE, JOB_REPLACE);
                }

                break;
        }

        case SIGUSR2: {
                FILE *f;
                char *dump = NULL;
                size_t size;

                if (!(f = open_memstream(&dump, &size))) {
                        log_warning("Failed to allocate memory stream.");
                        break;
                }

                manager_dump_units(m, f, "\t");
                manager_dump_jobs(m, f, "\t");

                if (ferror(f)) {
                        fclose(f);
                        free(dump);
                        log_warning("Failed to write status stream");
                        break;
                }

                fclose(f);
                log_dump(LOG_INFO, dump);
                free(dump);

                break;
        }

        case SIGHUP:
                m->exit_code = MANAGER_RELOAD;
                break;

        default:
                log_warning("Got unhandled signal <%s>.", signal_to_string(watch->signum));
        }


        if (sigchld)
                return (void) manager_dispatch_sigchld(m);
}

int manager_loop(Manager *m) {
        int r;

        RATELIMIT_DEFINE(rl, 1*USEC_PER_SEC, 50000);

        assert(m);
        m->exit_code = MANAGER_RUNNING;

        /* Release the path cache */
        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;

        manager_check_finished(m);

        /* There might still be some zombies hanging around from
         * before we were exec()'ed. Leat's reap them */
        r = manager_dispatch_sigchld(m);
        if (r < 0)
                return r;

        while (m->exit_code == MANAGER_RUNNING) {
                int n;
                int wait_msec = -1;

#ifdef Sys_Plat_Linux
                if (m->runtime_watchdog > 0 && m->running_as == SYSTEMD_SYSTEM)
                        watchdog_ping();
#endif

                if (!ratelimit_test(&rl)) {
                        /* Yay, something is going seriously wrong, pause a little */
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
                        continue;
                }

                if (manager_dispatch_load_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_queue(m) > 0)
                        continue;

                if (manager_dispatch_cleanup_queue(m) > 0)
                        continue;

#ifdef Use_CGroups
		if (manager_dispatch_cgroup_queue(m) > 0)
                        continue;
#endif

                if (manager_dispatch_run_queue(m) > 0)
                        continue;

                if (bus_dispatch(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

#ifdef Sys_Plat_Linux
                if (swap_dispatch_reload(m) > 0)
                        continue;
#endif

                n = ev_run(m->evloop, EVRUN_ONCE);
        }

        return m->exit_code;
}

int manager_load_unit_from_dbus_path(Manager *m, const char *s, DBusError *e, Unit **_u) {
        _cleanup_free_ char *n = NULL;
        Unit *u;
        int r;

        assert(m);
        assert(s);
        assert(_u);

        r = unit_name_from_dbus_path(s, &n);
        if (r < 0)
                return r;

        r = manager_load_unit(m, n, NULL, e, &u);
        if (r < 0)
                return r;

        *_u = u;

        return 0;
}

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j) {
        Job *j;
        unsigned id;
        int r;

        assert(m);
        assert(s);
        assert(_j);

        if (!startswith(s, "/org/freedesktop/systemd1/job/"))
                return -EINVAL;

        r = safe_atou(s + 30, &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return -ENOENT;

        *_j = j;

        return 0;
}

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success) {

#ifdef HAVE_AUDIT
        char *p;
        int audit_fd;

        audit_fd = get_audit_fd();
        if (audit_fd < 0)
                return;

        /* Don't generate audit events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        if (u->type != UNIT_SERVICE)
                return;

        p = unit_name_to_prefix_and_instance(u->id);
        if (!p) {
                log_error_unit(u->id,
                               "Failed to allocate unit name for audit message: %s", strerror(ENOMEM));
                return;
        }

        if (audit_log_user_comm_message(audit_fd, type, "", p, NULL, NULL, NULL, success) < 0) {
                if (errno == EPERM) {
                        /* We aren't allowed to send audit messages?
                         * Then let's not retry again. */
                        close_audit_fd();
                } else
                        log_warning("Failed to send audit message: %m");
        }

        free(p);
#endif

}

void manager_send_unit_plymouth(Manager *m, Unit *u) {
        int fd = -1;
        int r;
        union sockaddr_union sa;
        int n = 0;
        char *message = NULL;

        /* Don't generate plymouth events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        if (detect_container(NULL) > 0)
                return;

        if (u->type != UNIT_SERVICE
#ifdef Sys_Plat_Linux
            && u->type != UNIT_MOUNT &&
            u->type != UNIT_SWAP
#endif
            )
                return;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message then wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
                log_error("socket() failed: %m");
                return;
        }

	r = fd_cloexec(fd, true);
	r = r < 0 ? r : fd_nonblock(fd, true);

	if (r < 0) {
		log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
		close(fd);
		return;
	}

        zero(sa);
        sa.sa.sa_family = AF_UNIX;
        strncpy(sa.un.sun_path+1, "/org/freedesktop/plymouthd", sizeof(sa.un.sun_path)-1);
        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1)) < 0) {

                if (errno != EPIPE &&
                    errno != EAGAIN &&
                    errno != ENOENT &&
                    errno != ECONNREFUSED &&
                    errno != ECONNRESET &&
                    errno != ECONNABORTED)
                        log_error("connect() failed: %m");

                goto finish;
        }

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->id) + 1), u->id, &n) < 0) {
                log_oom();
                goto finish;
        }

        errno = 0;
        if (write(fd, message, n + 1) != n + 1) {

                if (errno != EPIPE &&
                    errno != EAGAIN &&
                    errno != ENOENT &&
                    errno != ECONNREFUSED &&
                    errno != ECONNRESET &&
                    errno != ECONNABORTED)
                        log_error("Failed to write Plymouth message: %m");

                goto finish;
        }

finish:
        safe_close(fd);

        free(message);
}

void manager_dispatch_bus_name_owner_changed(
                Manager *m,
                const char *name,
                const char* old_owner,
                const char *new_owner) {

        Unit *u;

        assert(m);
        assert(name);

        if (!(u = hashmap_get(m->watch_bus, name)))
                return;

        UNIT_VTABLE(u)->bus_name_owner_change(u, name, old_owner, new_owner);
}

void manager_dispatch_bus_query_pid_done(
                Manager *m,
                const char *name,
                pid_t pid) {

        Unit *u;

        assert(m);
        assert(name);
        assert(pid >= 1);

        if (!(u = hashmap_get(m->watch_bus, name)))
                return;

        UNIT_VTABLE(u)->bus_query_pid_done(u, name, pid);
}

int manager_open_serialization(Manager *m, FILE **_f) {
        char *path = NULL;
        int fd;
        FILE *f;

        assert(_f);

        asprintf(&path, "%s/dump-%lu-XXXXXX", m->iw_state_dir, (unsigned long) getpid());

        if (!path)
                return -ENOMEM;

        RUN_WITH_UMASK(0077) {
                fd = mkostemp(path, O_CLOEXEC);
        }

        if (fd < 0) {
                free(path);
                return -errno;
        }

        unlink(path);

        log_debug("Serializing state to %s", path);
        free(path);

        f = fdopen(fd, "w+");
        if (!f)
                return -errno;

        *_f = f;

        return 0;
}

#ifdef Use_PTGroups
static int manager_serialize_ptgroups(Manager *m, FILE *f, FDSet *fds, cJSON *out) {
        cJSON *oPtm = NULL, *oPtg_unit = NULL;
        Iterator i;
        PTGroup *key;
        Unit *val;
        int r;

        oPtg_unit = cJSON_CreateObject();

        r = ptmanager_to_json(m->pt_manager, &oPtm);
        if (r < 0)
                goto finish;

        HASHMAP_FOREACH_KEY (val, key, m->ptgroup_unit, i) {
                if (!cJSON_AddNumberToObject(oPtg_unit, val->id, key->id)) {
                        r = -ENOMEM;
                        break;
                }
        }

        if (!cJSON_AddItemToObject(out, "pt_manager", oPtm)) {
                r = -ENOMEM;
                goto finish;
        }

        oPtm = NULL;

        if (!cJSON_AddItemToObject(out, "ptgroup_unit", oPtg_unit)) {
                r = -ENOMEM;
                goto finish;
        }

        oPtg_unit = NULL;


finish:
        cJSON_Delete(oPtm);
        cJSON_Delete(oPtg_unit);

        return r;
}
#endif

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root) {
        /*
         * The new approach is to just output a JSON object, but not everything
         * has adopted that yet.
         */
        cJSON *obj;
        char *sObj = NULL;
        Iterator i;
        Unit *u;
        const char *t;
        char **e;
        int r;
#ifdef Use_KQProc
        int kqproc_fd;
#endif

        assert(m);
        assert(f);
        assert(fds);

        obj = cJSON_CreateObject();

        if (!obj)
                return -ENOMEM;

        m->n_reloading++;

        fprintf(f, "current-job-id=%i\n", m->current_job_id);
        fprintf(f, "taint-usr=%s\n", yes_no(m->taint_usr));
        fprintf(f, "n-installed-jobs=%u\n", m->n_installed_jobs);
        fprintf(f, "n-failed-jobs=%u\n", m->n_failed_jobs);

        dual_timestamp_serialize(f, "firmware-timestamp", &m->firmware_timestamp);
        dual_timestamp_serialize(f, "kernel-timestamp", &m->kernel_timestamp);
        dual_timestamp_serialize(f, "loader-timestamp", &m->loader_timestamp);
        dual_timestamp_serialize(f, "initrd-timestamp", &m->initrd_timestamp);

        if (!in_initrd()) {
                dual_timestamp_serialize(f, "userspace-timestamp", &m->userspace_timestamp);
                dual_timestamp_serialize(f, "finish-timestamp", &m->finish_timestamp);
        }

        if (!switching_root) {
                STRV_FOREACH (e, m->environment) {
                        _cleanup_free_ char *ce;

                        ce = cescape(*e);
                        if (ce)
                                fprintf(f, "env=%s\n", *e);
                }
        }

        bus_serialize(m, f);

#ifdef Use_KQProc
        kqproc_fd = fdset_put_dup(fds, m->kqproc_io.fd);
        if (kqproc_fd < 0) {
                r = -errno;
                goto finish;
        }

        if (!cJSON_AddNumberToObject(obj, "kqproc_fd", kqproc_fd)) {
                r = -ENOMEM;
                goto finish;
        }
#endif
#ifdef Use_PTGroups
        r = manager_serialize_ptgroups(m, f, fds, obj);
        if (r < 0) {
                m->n_reloading--;
                return r;
        }
#endif

        fputc('\n', f);

        sObj = cJSON_Print(obj);
        if (!sObj) {
                r = -ENOMEM;
                goto finish;
        }

        fputs(sObj, f);

        fputs("\n\n", f);

        HASHMAP_FOREACH_KEY (u, t, m->units, i) {
                if (u->id != t)
                        continue;

                /* Start marker */
                fputs(u->id, f);
                fputc('\n', f);

                r = unit_serialize(u, f, fds, !switching_root);
                if (r < 0) {
                        m->n_reloading--;
                        return r;
                }
        }

        assert(m->n_reloading > 0);
        m->n_reloading--;

        if (ferror(f))
                return -EIO;

        r = bus_fdset_add_all(m, fds);
        if (r < 0)
                return r;

finish:
        cJSON_Delete(obj);

        return r;
}

/* deserialise the JSON serialisation object */
int manager_deserialise_object(Manager *m, cJSON *obj, FDSet *fds) {
        int r = 0;
#ifdef Use_KQProc
        cJSON *oKqproc_fd;
#endif
#ifdef Use_PTGroups
        cJSON *oPtm;
        cJSON *oPtg_unit;

        cJSON *oEntry; /* hashmap entry */
#endif

#ifdef Use_KQProc
        oKqproc_fd = cJSON_GetObjectItem(obj, "kqproc_fd");
        if (!oKqproc_fd) {
                log_error("Failed to deserialise PROC Kernel Queue FD\n");
                r = -EINVAL;
                goto finish;
        } else {
                int fd;

                assert(cJSON_IsNumber(oKqproc_fd));

                fd = cJSON_GetNumberValue(oKqproc_fd);
                fd = fdset_remove(fds, fd);

                assert(fd > 0);

                r = manager_setup_kqproc_watch(m, fd);
                if (r < 0)
                        goto finish;
        }
#endif
#ifdef Use_PTGroups
        oPtm = cJSON_GetObjectItem(obj, "pt_manager");
        oPtg_unit = cJSON_GetObjectItem(obj, "ptgroup_unit");

        if (!oPtm || !oPtg_unit) {
                log_error("Failed to deserialise PTGroups information\n");
                r = -EINVAL;
                goto finish;
        }

        m->pt_manager = ptmanager_new_from_json(m, oPtm);
        if (!m->pt_manager) {
                log_error("Failed to deserialise PTGroups\n");
                r = -ENOMEM;
                goto finish;
        }

        cJSON_ArrayForEach(oEntry, oPtg_unit) {
                Unit *u;
                PTGroup *grp;

                r = manager_load_unit(m, oEntry->string, NULL, NULL, &u);

                if (r < 0) {
                        log_error("Failed to do initial load of unit %s\n", oEntry->string);
                        goto finish;
                }

                grp = ptmanager_find_ptg_by_id(m->pt_manager, oEntry->valueint);

                if (!grp) {
                        log_error(
                                "Failed to find PTGroup for ID %d (for unit %s)\n",
                                oEntry->valueint,
                                oEntry->string);
                        goto finish;
                }

                r = hashmap_put(m->ptgroup_unit, grp, u);
                if (r < 0) {
                        log_error(
                                "Failed to insert PTGroup for unit %s into hashmap: %s\n",
                                u->id,
                                strerror(-r));
                        goto finish;
                }

                u->cgroup_realized = 1;
                u->ptgroup = grp;
        }


#endif

finish:
        return r;
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r = 0;
        char **jsonv = NULL;
        char *json = NULL;
        cJSON *obj = NULL;

        assert(m);
        assert(f);

        m->n_reloading++;

        for (;;) {
                char line[LINE_MAX], *l;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                r = 0;
                        else
                                r = -errno;

                        goto finish;
                }

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0)
                        break;

                if (startswith(l, "current-job-id=")) {
                        uint32_t id;

                        if (safe_atou32(l + 15, &id) < 0)
                                log_debug("Failed to parse current job id value %s", l + 15);
                        else
                                m->current_job_id = MAX(m->current_job_id, id);
                } else if (startswith(l, "n-installed-jobs=")) {
                        uint32_t n;

                        if (safe_atou32(l + 17, &n) < 0)
                                log_debug("Failed to parse installed jobs counter %s", l + 17);
                        else
                                m->n_installed_jobs += n;
                } else if (startswith(l, "n-failed-jobs=")) {
                        uint32_t n;

                        if (safe_atou32(l + 14, &n) < 0)
                                log_debug("Failed to parse failed jobs counter %s", l + 14);
                        else
                                m->n_failed_jobs += n;
                } else if (startswith(l, "taint-usr=")) {
                        int b;

                        if ((b = parse_boolean(l + 10)) < 0)
                                log_debug("Failed to parse taint /usr flag %s", l + 10);
                        else
                                m->taint_usr = m->taint_usr || b;
                } else if (startswith(l, "firmware-timestamp="))
                        dual_timestamp_deserialize(l + 19, &m->firmware_timestamp);
                else if (startswith(l, "loader-timestamp="))
                        dual_timestamp_deserialize(l + 17, &m->loader_timestamp);
                else if (startswith(l, "kernel-timestamp="))
                        dual_timestamp_deserialize(l + 17, &m->kernel_timestamp);
                else if (startswith(l, "initrd-timestamp="))
                        dual_timestamp_deserialize(l + 17, &m->initrd_timestamp);
                else if (startswith(l, "userspace-timestamp="))
                        dual_timestamp_deserialize(l + 20, &m->userspace_timestamp);
                else if (startswith(l, "finish-timestamp="))
                        dual_timestamp_deserialize(l + 17, &m->finish_timestamp);
                else if (startswith(l, "env=")) {
                        _cleanup_free_ char *uce = NULL;
                        char **e;

                        uce = cunescape(l + 4);
                        if (!uce) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        e = strv_env_set(m->environment, uce);
                        if (!e) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        strv_free(m->environment);
                        m->environment = e;
                } else if (bus_deserialize_item(m, l) == 0)
                        log_debug("Unknown serialization item '%s'", l);
        }

        for (;;) {
                char line[LINE_MAX], *l;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                r = 0;
                        else
                                r = -errno;

                        goto finish;
                }

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0)
                        break;

                if (!jsonv)
                        jsonv = strv_new(l, NULL);
                else if (strv_extend(&jsonv, l) < 0) {
                        r = log_oom();
                        goto finish;
                }
        }

        json = strv_join(jsonv, "\n");
        strv_free(jsonv);
        jsonv = NULL;

        obj = cJSON_Parse(json);
        if (!obj) {
                log_error("Failed to parse serialised JSON.\n");
                r = -EINVAL;
                goto finish;
        }

        free(json);
        json = NULL;

        r = manager_deserialise_object(m, obj, fds);
        if (!r)
                goto finish;

        for (;;) {
                Unit *u;
                char name[UNIT_NAME_MAX + 2];

                /* Start marker */
                if (!fgets(name, sizeof(name), f)) {
                        if (feof(f))
                                r = 0;
                        else
                                r = -errno;

                        goto finish;
                }

                char_array_0(name);

                r = manager_load_unit(m, strstrip(name), NULL, NULL, &u);
                if (r < 0)
                        goto finish;

                r = unit_deserialize(u, f, fds);
                if (r < 0)
                        goto finish;
        }

finish:
        if (ferror(f))
                r = -EIO;

        assert(m->n_reloading > 0);
        m->n_reloading--;

        free(json);
        strv_free(jsonv);
        cJSON_Delete(obj);

        return r;
}

int manager_distribute_fds(Manager *m, FDSet *fds) {
        Unit *u;
        Iterator i;
        int r;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i) {

                if (fdset_size(fds) <= 0)
                        break;

                if (UNIT_VTABLE(u)->distribute_fds) {
                        r = UNIT_VTABLE(u)->distribute_fds(u, fds);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int manager_reload(Manager *m) {
        int r, q;
        FILE *f = NULL;
        FDSet *fds;

        assert(m);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return r;

        m->n_reloading ++;
        bus_broadcast_reloading(m, true);

        fds = fdset_new();
        if (!fds) {
                m->n_reloading --;
                r = -ENOMEM;
                goto finish;
        }

        r = manager_serialize(m, f, fds, false);
        if (r < 0) {
                m->n_reloading --;
                goto finish;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                m->n_reloading --;
                r = -errno;
                goto finish;
        }

        /* From here on there is no way back. */
#ifdef Use_PTGroups
        ptg_release(&m->pt_manager->group);
        hashmap_clear(m->ptgroup_unit);
#endif
        manager_clear_jobs_and_units(m);
        manager_undo_generators(m);
        lookup_paths_free(&m->lookup_paths);

        /* Find new unit paths */
        manager_run_generators(m);

        q = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
                        NULL,
                        m->generator_unit_path,
                        m->generator_unit_path_early,
                        m->generator_unit_path_late);
        if (q < 0)
                r = q;

        manager_build_unit_path_cache(m);

        /* First, enumerate what we can from all config files */
        q = manager_enumerate(m);
        if (q < 0)
                r = q;

        /* Second, deserialize our stored data */
        q = manager_deserialize(m, f, fds);
        if (q < 0)
                r = q;

        fclose(f);
        f = NULL;

        /* Third, fire things up! */
        q = manager_coldplug(m);
        if (q < 0)
                r = q;

        assert(m->n_reloading > 0);
        m->n_reloading--;

        m->send_reloading_done = true;

finish:
        if (f)
                fclose(f);

        if (fds)
                fdset_free(fds);

        return r;
}

static bool manager_is_booting_or_shutting_down(Manager *m) {
        Unit *u;

        assert(m);

        /* Is the initial job still around? */
        if (manager_get_job(m, m->default_unit_job_id))
                return true;

        /* Is there a job for the shutdown target? */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u)
                return !!u->job;

        return false;
}

bool manager_is_reloading_or_reexecuting(Manager *m) {
        assert(m);

        return m->n_reloading != 0;
}

void manager_reset_failed(Manager *m) {
        Unit *u;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i)
                unit_reset_failed(u);
}

bool manager_unit_inactive_or_pending(Manager *m, const char *name) {
        Unit *u;

        assert(m);
        assert(name);

        /* Returns true if the unit is inactive or going down */
        u = manager_get_unit(m, name);
        if (!u)
                return true;

        return unit_inactive_or_pending(u);
}

void manager_check_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        assert(m);

        if (m->n_running_jobs == 0)
                manager_unwatch_jobs_in_progress(m);

        if (hashmap_size(m->jobs) > 0) {
                manager_jobs_in_progress_mod_timer(m);
                return;
        }

        /* Notify Type=idle units that we are done now */
        manager_unwatch_idle_pipe(m);
        close_idle_pipe(m);

        /* Turn off confirm spawn now */
        m->confirm_spawn = false;

        if (dual_timestamp_is_set(&m->finish_timestamp))
                return;

        dual_timestamp_get(&m->finish_timestamp);

        if (m->running_as == SYSTEMD_SYSTEM && detect_container(NULL) <= 0) {

                /* Note that m->kernel_usec.monotonic is always at 0,
                 * and m->firmware_usec.monotonic and
                 * m->loader_usec.monotonic should be considered
                 * negative values. */

                firmware_usec = m->firmware_timestamp.monotonic - m->loader_timestamp.monotonic;
                loader_usec = m->loader_timestamp.monotonic - m->kernel_timestamp.monotonic;
                userspace_usec = m->finish_timestamp.monotonic - m->userspace_timestamp.monotonic;
                total_usec = m->firmware_timestamp.monotonic + m->finish_timestamp.monotonic;

                if (dual_timestamp_is_set(&m->initrd_timestamp)) {

                        kernel_usec = m->initrd_timestamp.monotonic - m->kernel_timestamp.monotonic;
                        initrd_usec = m->userspace_timestamp.monotonic - m->initrd_timestamp.monotonic;

                        if (!log_on_console())
                                log_struct(LOG_INFO,
                                           MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                           "KERNEL_USEC=%llu", (unsigned long long) kernel_usec,
                                           "INITRD_USEC=%llu", (unsigned long long) initrd_usec,
                                           "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                           "MESSAGE=Startup finished in %s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                           format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                           format_timespan(initrd, sizeof(initrd), initrd_usec, USEC_PER_MSEC),
                                           format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                           format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                           NULL);
                } else {
                        kernel_usec = m->userspace_timestamp.monotonic - m->kernel_timestamp.monotonic;
                        initrd_usec = 0;

                        if (!log_on_console())
                                log_struct(LOG_INFO,
                                           MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                           "KERNEL_USEC=%llu", (unsigned long long) kernel_usec,
                                           "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                           "MESSAGE=Startup finished in %s (kernel) + %s (userspace) = %s.",
                                           format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                           format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                           format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                           NULL);
                }
        } else {
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->finish_timestamp.monotonic - m->userspace_timestamp.monotonic;

                if (!log_on_console())
                        log_struct(LOG_INFO,
                                   MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                   "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                   "MESSAGE=Startup finished in %s.",
                                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                   NULL);
        }

        bus_broadcast_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false,
                   "READY=1\nSTATUS=Startup finished in %s.",
                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC));
}

static int create_generator_dir(Manager *m, char **generator, const char *name) {
        char *p;
        int r;

        assert(m);
        assert(generator);
        assert(name);

        if (*generator)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM && getpid() == 1) {

		p = strappend(INSTALL_PKGRUNSTATE_DIR "/", name);
		if (!p)
			return log_oom();

                r = mkdir_p_label(p, 0755);
                if (r < 0) {
                        log_error("Failed to create generator directory %s: %s",
                                  p, strerror(-r));
                        free(p);
                        return r;
                }
        } else {
                p = strjoin("/tmp/systemd-", name, ".XXXXXX", NULL);
                if (!p)
                        return log_oom();

                if (!mkdtemp(p)) {
                        log_error("Failed to create generator directory %s: %m",
                                  p);
                        free(p);
                        return -errno;
                }
        }

        *generator = p;
        return 0;
}

static void trim_generator_dir(Manager *m, char **generator) {
        assert(m);
        assert(generator);

        if (!*generator)
                return;

        if (rmdir(*generator) >= 0) {
                free(*generator);
                *generator = NULL;
        }

        return;
}

void manager_run_generators(Manager *m) {
        DIR *d = NULL;
        const char *generator_path;
        const char *argv[5];
        int r;

        assert(m);

        generator_path = m->running_as == SYSTEMD_SYSTEM ? SYSTEM_GENERATOR_PATH : USER_GENERATOR_PATH;
        d = opendir(generator_path);
        if (!d) {
                if (errno == ENOENT)
                        return;

                log_error("Failed to enumerate generator directory %s: %m",
                          generator_path);
                return;
        }

        r = create_generator_dir(m, &m->generator_unit_path, "generator");
        if (r < 0)
                goto finish;

        r = create_generator_dir(m, &m->generator_unit_path_early, "generator.early");
        if (r < 0)
                goto finish;

        r = create_generator_dir(m, &m->generator_unit_path_late, "generator.late");
        if (r < 0)
                goto finish;

        argv[0] = NULL; /* Leave this empty, execute_directory() will fill something in */
        argv[1] = m->generator_unit_path;
        argv[2] = m->generator_unit_path_early;
        argv[3] = m->generator_unit_path_late;
        argv[4] = NULL;

        RUN_WITH_UMASK(0022)
                execute_directory(generator_path, d, DEFAULT_TIMEOUT_USEC, (char**) argv);

        trim_generator_dir(m, &m->generator_unit_path);
        trim_generator_dir(m, &m->generator_unit_path_early);
        trim_generator_dir(m, &m->generator_unit_path_late);

finish:
        if (d)
                closedir(d);
}

static void remove_generator_dir(Manager *m, char **generator) {
        assert(m);
        assert(generator);

        if (!*generator)
                return;

        strv_remove(m->lookup_paths.unit_path, *generator);
        rm_rf(*generator, false, true, false);

        free(*generator);
        *generator = NULL;
}

void manager_undo_generators(Manager *m) {
        assert(m);

        remove_generator_dir(m, &m->generator_unit_path);
        remove_generator_dir(m, &m->generator_unit_path_early);
        remove_generator_dir(m, &m->generator_unit_path_late);
}

int manager_environment_add(Manager *m, char **environment) {
        char **e = NULL;
        assert(m);

        e = strv_env_merge(2, m->environment, environment);
        if (!e)
                return -ENOMEM;

        strv_free(m->environment);
        m->environment = e;

        return 0;
}

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit) {
        int i;

        assert(m);

        for (i = 0; i < RLIM_NLIMITS; i++) {
                if (!default_rlimit[i])
                        continue;

                m->rlimit[i] = newdup(struct rlimit, default_rlimit[i], 1);
                if (!m->rlimit[i])
                        return -ENOMEM;
        }

        return 0;
}

void manager_recheck_journal(Manager *m) {
        Unit *u;

        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        u = manager_get_unit(m, SPECIAL_JOURNALD_SOCKET);
        if (u && SOCKET(u)->state != SOCKET_RUNNING) {
                log_close_journal();
                return;
        }

        u = manager_get_unit(m, SPECIAL_JOURNALD_SERVICE);
        if (u && SERVICE(u)->state != SERVICE_RUNNING) {
                log_close_journal();
                return;
        }

	/* Hmm, OK, so the socket is fully up and the service is up
         * too, then let's make use of the thing. */
        log_open();
}

void manager_set_show_status(Manager *m, bool b) {
        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        m->show_status = b;

        if (b)
		touch(INSTALL_PKGRUNSTATE_DIR "/show-status");
	else
		unlink(INSTALL_PKGRUNSTATE_DIR "/show-status");
}

static bool manager_get_show_status(Manager *m) {
        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return false;

        if (m->no_console_output)
                return false;

        if (m->show_status)
                return true;

        /* If Plymouth is running make sure we show the status, so
         * that there's something nice to see when people press Esc */

        return plymouth_running();
}

void manager_status_printf(Manager *m, bool ephemeral, const char *status, const char *format, ...) {
        va_list ap;

        if (!manager_get_show_status(m))
                return;

        /* XXX We should totally drop the check for ephemeral here
         * and thus effectively make 'Type=idle' pointless. */
        if (ephemeral && m->n_on_console > 0)
                return;

        if (!manager_is_booting_or_shutting_down(m))
                return;

        va_start(ap, format);
        status_vprintf(status, true, ephemeral, format, ap);
        va_end(ap);
}

int manager_get_unit_by_path(Manager *m, const char *path, const char *suffix, Unit **_found) {
        _cleanup_free_ char *p = NULL;
        Unit *found;

        assert(m);
        assert(path);
        assert(suffix);
        assert(_found);

        p = unit_name_from_path(path, suffix);
        if (!p)
                return -ENOMEM;

        found = manager_get_unit(m, p);
        if (!found) {
                *_found = NULL;
                return 0;
        }

        *_found = found;
        return 1;
}

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path) {
        char p[strlen(path)+1];

        assert(m);
        assert(path);

        strcpy(p, path);
        path_kill_slashes(p);

        return hashmap_get(m->units_requiring_mounts_for, streq(p, "/") ? "" : p);
}
