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

#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/reboot.h>

#include "async.h"
#include "ev-util.h"
#include "manager.h"
#include "service.h"
#include "unit.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "dbus-service.h"
#include "special.h"
#include "dbus-common.h"
#include "exit-status.h"
#include "def.h"
#include "path-util.h"
#include "util.h"
#include "utf8.h"
#include "env-util.h"
#include "fileio.h"

#ifdef Sys_Plat_NetBSD /* FIXME cleanup */
#define reboot(m) reboot(m, NULL)
#endif

#ifdef HAVE_SYSV_COMPAT

#define DEFAULT_SYSV_TIMEOUT_USEC (5*USEC_PER_MINUTE)

typedef enum RunlevelType {
        RUNLEVEL_UP,
        RUNLEVEL_DOWN
} RunlevelType;

static const struct {
        const char *path;
        const char *target;
        const RunlevelType type;
} rcnd_table[] = {
        /* Standard SysV runlevels for start-up */
        { "rc1.d",  SPECIAL_RESCUE_TARGET,    RUNLEVEL_UP },
        { "rc2.d",  SPECIAL_RUNLEVEL2_TARGET, RUNLEVEL_UP },
        { "rc3.d",  SPECIAL_RUNLEVEL3_TARGET, RUNLEVEL_UP },
        { "rc4.d",  SPECIAL_RUNLEVEL4_TARGET, RUNLEVEL_UP },
        { "rc5.d",  SPECIAL_RUNLEVEL5_TARGET, RUNLEVEL_UP },

        /* Standard SysV runlevels for shutdown */
        { "rc0.d",  SPECIAL_POWEROFF_TARGET,  RUNLEVEL_DOWN },
        { "rc6.d",  SPECIAL_REBOOT_TARGET,    RUNLEVEL_DOWN }

        /* Note that the order here matters, as we read the
           directories in this order, and we want to make sure that
           sysv_start_priority is known when we first load the
           unit. And that value we only know from S links. Hence
           UP must be read before DOWN */
};

#define RUNLEVELS_UP "12345"
#endif

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

/* For Type=idle we never want to delay any other jobs, hence we
 * consider idle jobs active as soon as we start working on them */
static const UnitActiveState state_translation_table_idle[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVE,
        [SERVICE_START] = UNIT_ACTIVE,
        [SERVICE_START_POST] = UNIT_ACTIVE,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

static void service_init(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_start_usec = u->manager->default_timeout_start_usec;
        s->timeout_stop_usec = u->manager->default_timeout_stop_usec;
        s->restart_usec = u->manager->default_restart_usec;
        s->type = _SERVICE_TYPE_INVALID;

        ev_timer_zero(s->watchdog_watch);
        ev_timer_zero(s->timer_watch);

#ifdef HAVE_SYSV_COMPAT
        s->sysv_start_priority = -1;
        s->sysv_start_priority_from_rcnd = -1;
#endif
        s->socket_fd = -1;
        s->guess_main_pid = true;

        exec_context_init(&s->exec_context);
        kill_context_init(&s->kill_context);
#ifdef Use_CGroups
        cgroup_context_init(&s->cgroup_context);
#endif

        RATELIMIT_INIT(s->start_limit,
                       u->manager->default_start_limit_interval,
                       u->manager->default_start_limit_burst);

        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
}

static void service_unwatch_control_pid(Service *s) {
        assert(s);

        if (s->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->control_pid);
        s->control_pid = 0;
}

static void service_unwatch_main_pid(Service *s) {
        assert(s);

        if (s->main_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->main_pid);
        s->main_pid = 0;
}

static void service_unwatch_pid_file(Service *s) {
        if (!s->pid_file_pathspec)
                return;

        log_debug_unit(UNIT(s)->id, "Stopping watch for %s's PID file %s",
                       UNIT(s)->id, s->pid_file_pathspec->path);
        path_spec_unwatch(s->pid_file_pathspec, UNIT(s));
        path_spec_done(s->pid_file_pathspec);
        free(s->pid_file_pathspec);
        s->pid_file_pathspec = NULL;
}

static int service_set_main_pid(Service *s, pid_t pid) {
        pid_t ppid;

        assert(s);

        if (pid <= 1)
                return -EINVAL;

        if (pid == getpid())
                return -EINVAL;

        if (s->main_pid == pid && s->main_pid_known)
                return 0;

        if (s->main_pid != pid) {
                service_unwatch_main_pid(s);
                exec_status_start(&s->main_exec_status, pid);
        }

        s->main_pid = pid;
        s->main_pid_known = true;

        if (get_parent_of_pid(pid, &ppid) >= 0 && ppid != getpid()) {
                log_warning_unit(UNIT(s)->id,
                                 "%s: Supervising process %lu which is not our child. We'll most likely not notice when it exits.",
                                 UNIT(s)->id, (unsigned long) pid);

                s->main_pid_alien = true;
        } else
                s->main_pid_alien = false;

        return 0;
}

static void service_close_socket_fd(Service *s) {
        assert(s);

        if (s->socket_fd < 0)
                return;

        s->socket_fd = asynchronous_close(s->socket_fd);
}

static void service_connection_unref(Service *s) {
        assert(s);

        if (!UNIT_ISSET(s->accept_socket))
                return;

        socket_connection_unref(SOCKET(UNIT_DEREF(s->accept_socket)));
        unit_ref_unset(&s->accept_socket);
}

static void service_stop_watchdog(Service *s) {
        assert(s);

        unit_unwatch_timer(UNIT(s), &s->watchdog_watch);
        s->watchdog_timestamp.realtime = 0;
        s->watchdog_timestamp.monotonic = 0;
}

static void service_enter_signal(Service *s, ServiceState state, ServiceResult f);

static void service_handle_watchdog(Service *s) {
        usec_t offset;
        int r;

        assert(s);

        if (s->watchdog_usec == 0)
                return;

        offset = now(CLOCK_MONOTONIC) - s->watchdog_timestamp.monotonic;
        if (offset >= s->watchdog_usec) {
                log_error_unit(UNIT(s)->id, "%s watchdog timeout!", UNIT(s)->id);
                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_WATCHDOG);
                return;
        }

        r = unit_watch_timer(UNIT(s), s->watchdog_usec - offset, &s->watchdog_watch);
        if (r < 0)
                log_warning_unit(UNIT(s)->id,
                                 "%s failed to install watchdog timer: %s",
                                 UNIT(s)->id, strerror(-r));
}

static void service_reset_watchdog(Service *s) {
        assert(s);

        dual_timestamp_get(&s->watchdog_timestamp);
        service_handle_watchdog(s);
}

static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        free(s->pid_file);
        s->pid_file = NULL;

#ifdef HAVE_SYSV_COMPAT
        free(s->sysv_runlevels);
        s->sysv_runlevels = NULL;
#endif

        free(s->status_text);
        s->status_text = NULL;

#ifdef Use_CGroups
        cgroup_context_done(&s->cgroup_context);
#endif
        exec_context_done(&s->exec_context, manager_is_reloading_or_reexecuting(u->manager));
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
        s->control_command = NULL;
        s->main_command = NULL;

        set_free(s->restart_ignore_status.code);
        s->restart_ignore_status.code = NULL;
        set_free(s->restart_ignore_status.signal);
        s->restart_ignore_status.signal = NULL;

        set_free(s->success_status.code);
        s->success_status.code = NULL;
        set_free(s->success_status.signal);
        s->success_status.signal = NULL;

        /* This will leak a process, but at least no memory or any of
         * our resources */
        service_unwatch_main_pid(s);
        service_unwatch_control_pid(s);
        service_unwatch_pid_file(s);

        if (s->bus_name)  {
                unit_unwatch_bus_name(u, s->bus_name);
                free(s->bus_name);
                s->bus_name = NULL;
        }

        service_close_socket_fd(s);
        service_connection_unref(s);

        unit_ref_unset(&s->accept_socket);

        service_stop_watchdog(s);

        unit_unwatch_timer(u, &s->timer_watch);
}

#ifdef HAVE_SYSV_COMPAT
static char *sysv_translate_name(const char *name) {
        char *r;

        r = new(char, strlen(name) + sizeof(".service"));
        if (!r)
                return NULL;

        if (endswith(name, ".sh"))
                /* Drop .sh suffix */
                strcpy(stpcpy(r, name) - 3, ".service");
        else
                /* Normal init script name */
                strcpy(stpcpy(r, name), ".service");

        return r;
}

static int sysv_translate_facility(const char *name, const char *filename, char **_r) {

        /* We silently ignore the $ prefix here. According to the LSB
         * spec it simply indicates whether something is a
         * standardized name or a distribution-specific one. Since we
         * just follow what already exists and do not introduce new
         * uses or names we don't care who introduced a new name. */

        static const char * const table[] = {
                /* LSB defined facilities */
                "local_fs",             NULL,
                "network",              SPECIAL_NETWORK_ONLINE_TARGET,
                "named",                SPECIAL_NSS_LOOKUP_TARGET,
                "portmap",              SPECIAL_RPCBIND_TARGET,
                "remote_fs",            SPECIAL_REMOTE_FS_TARGET,
                "syslog",               NULL,
                "time",                 SPECIAL_TIME_SYNC_TARGET,
        };

        unsigned i;
        char *r;
        const char *n;

        assert(name);
        assert(_r);

        n = *name == '$' ? name + 1 : name;

        for (i = 0; i < ELEMENTSOF(table); i += 2) {

                if (!streq(table[i], n))
                        continue;

                if (!table[i+1])
                        return 0;

                r = strdup(table[i+1]);
                if (!r)
                        return log_oom();

                goto finish;
        }

        /* If we don't know this name, fallback heuristics to figure
         * out whether something is a target or a service alias. */

        if (*name == '$') {
                if (!unit_prefix_is_valid(n))
                        return -EINVAL;

                /* Facilities starting with $ are most likely targets */
                r = unit_name_build(n, NULL, ".target");
        } else if (filename && streq(name, filename))
                /* Names equaling the file name of the services are redundant */
                return 0;
        else
                /* Everything else we assume to be normal service names */
                r = sysv_translate_name(n);

        if (!r)
                return -ENOMEM;

finish:
        *_r = r;

        return 1;
}

static int sysv_fix_order(Service *s) {
        Unit *other;
        int r;

        assert(s);

        if (s->sysv_start_priority < 0)
                return 0;

        /* For each pair of services where at least one lacks a LSB
         * header, we use the start priority value to order things. */

        IWLIST_FOREACH(units_by_type, other, UNIT(s)->manager->units_by_type[UNIT_SERVICE]) {
                Service *t;
                UnitDependency d;
                bool special_s, special_t;

                t = SERVICE(other);

                if (s == t)
                        continue;

                if (UNIT(t)->load_state != UNIT_LOADED)
                        continue;

                if (t->sysv_start_priority < 0)
                        continue;

                /* If both units have modern headers we don't care
                 * about the priorities */
                if ((UNIT(s)->fragment_path || s->sysv_has_lsb) &&
                    (UNIT(t)->fragment_path || t->sysv_has_lsb))
                        continue;

                special_s = s->sysv_runlevels && !chars_intersect(RUNLEVELS_UP, s->sysv_runlevels);
                special_t = t->sysv_runlevels && !chars_intersect(RUNLEVELS_UP, t->sysv_runlevels);

                if (special_t && !special_s)
                        d = UNIT_AFTER;
                else if (special_s && !special_t)
                        d = UNIT_BEFORE;
                else if (t->sysv_start_priority < s->sysv_start_priority)
                        d = UNIT_AFTER;
                else if (t->sysv_start_priority > s->sysv_start_priority)
                        d = UNIT_BEFORE;
                else
                        continue;

                /* FIXME: Maybe we should compare the name here lexicographically? */

                if ((r = unit_add_dependency(UNIT(s), d, UNIT(t), true)) < 0)
                        return r;
        }

        return 0;
}

static ExecCommand *exec_command_new(const char *path, const char *arg1) {
        ExecCommand *c;

        if (!(c = new0(ExecCommand, 1)))
                return NULL;

        if (!(c->path = strdup(path))) {
                free(c);
                return NULL;
        }

        if (!(c->argv = strv_new(path, arg1, NULL))) {
                free(c->path);
                free(c);
                return NULL;
        }

        return c;
}

static int sysv_exec_commands(Service *s, const bool supports_reload) {
        ExecCommand *c;

        assert(s);
        assert(s->is_sysv);
        assert(UNIT(s)->source_path);

        c = exec_command_new(UNIT(s)->source_path, "start");
        if (!c)
                return -ENOMEM;
        exec_command_append_list(s->exec_command+SERVICE_EXEC_START, c);

        c = exec_command_new(UNIT(s)->source_path, "stop");
        if (!c)
                return -ENOMEM;
        exec_command_append_list(s->exec_command+SERVICE_EXEC_STOP, c);

        if (supports_reload) {
                c = exec_command_new(UNIT(s)->source_path, "reload");
                if (!c)
                        return -ENOMEM;
                exec_command_append_list(s->exec_command+SERVICE_EXEC_RELOAD, c);
        }

        return 0;
}

static bool usage_contains_reload(const char *line) {
        return (strcasestr(line, "{reload|") ||
                strcasestr(line, "{reload}") ||
                strcasestr(line, "{reload\"") ||
                strcasestr(line, "|reload|") ||
                strcasestr(line, "|reload}") ||
                strcasestr(line, "|reload\""));
}

static int service_load_sysv_path(Service *s, const char *path) {
        FILE *f;
        Unit *u;
        unsigned line = 0;
        int r;
        enum {
                NORMAL,
                DESCRIPTION,
                LSB,
                LSB_DESCRIPTION,
                USAGE_CONTINUATION
        } state = NORMAL;
        char *short_description = NULL, *long_description = NULL, *chkconfig_description = NULL, *description;
        struct stat st;
        bool supports_reload = false;

        assert(s);
        assert(path);

        u = UNIT(s);

        f = fopen(path, "re");
        if (!f) {
                r = errno == ENOENT ? 0 : -errno;
                goto finish;
        }

        if (fstat(fileno(f), &st) < 0) {
                r = -errno;
                goto finish;
        }

        free(u->source_path);
        u->source_path = strdup(path);
        if (!u->source_path) {
                r = -ENOMEM;
                goto finish;
        }
        u->source_mtime = timespec_load(&st.st_mtim);

        if (null_or_empty(&st)) {
                u->load_state = UNIT_MASKED;
                r = 0;
                goto finish;
        }

        s->is_sysv = true;

        while (!feof(f)) {
                char l[LINE_MAX], *t;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        log_error_unit(u->id,
                                       "Failed to read configuration file '%s': %s",
                                       path, strerror(-r));
                        goto finish;
                }

                line++;

                t = strstrip(l);
                if (*t != '#') {
                        /* Try to figure out whether this init script supports
                         * the reload operation. This heuristic looks for
                         * "Usage" lines which include the reload option. */
                        if ( state == USAGE_CONTINUATION ||
                            (state == NORMAL && strcasestr(t, "usage"))) {
                                if (usage_contains_reload(t)) {
                                        supports_reload = true;
                                        state = NORMAL;
                                } else if (t[strlen(t)-1] == '\\')
                                        state = USAGE_CONTINUATION;
                                else
                                        state = NORMAL;
                        }

                        continue;
                }

                if (state == NORMAL && streq(t, "### BEGIN INIT INFO")) {
                        state = LSB;
                        s->sysv_has_lsb = true;
                        continue;
                }

                if ((state == LSB_DESCRIPTION || state == LSB) && streq(t, "### END INIT INFO")) {
                        state = NORMAL;
                        continue;
                }

                t++;
                t += strspn(t, WHITESPACE);

                if (state == NORMAL) {

                        /* Try to parse Red Hat style chkconfig headers */

                        if (startswith_no_case(t, "chkconfig:")) {
                                int start_priority;
                                char runlevels[16], *k;

                                state = NORMAL;

                                if (sscanf(t+10, "%15s %i %*i",
                                           runlevels,
                                           &start_priority) != 2) {

                                        log_warning_unit(u->id,
                                                         "[%s:%u] Failed to parse chkconfig line. Ignoring.",
                                                         path, line);
                                        continue;
                                }

                                /* A start priority gathered from the
                                 * symlink farms is preferred over the
                                 * data from the LSB header. */
                                if (start_priority < 0 || start_priority > 99)
                                        log_warning_unit(u->id,
                                                         "[%s:%u] Start priority out of range. Ignoring.",
                                                         path, line);
                                else
                                        s->sysv_start_priority = start_priority;

                                char_array_0(runlevels);
                                k = delete_chars(runlevels, WHITESPACE "-");

                                if (k[0]) {
                                        char *d;

                                        if (!(d = strdup(k))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        free(s->sysv_runlevels);
                                        s->sysv_runlevels = d;
                                }

                        } else if (startswith_no_case(t, "description:")) {

                                size_t k = strlen(t);
                                char *d;
                                const char *j;

                                if (t[k-1] == '\\') {
                                        state = DESCRIPTION;
                                        t[k-1] = 0;
                                }

                                if ((j = strstrip(t+12)) && *j) {
                                        if (!(d = strdup(j))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }
                                } else
                                        d = NULL;

                                free(chkconfig_description);
                                chkconfig_description = d;

                        } else if (startswith_no_case(t, "pidfile:")) {

                                char *fn;

                                state = NORMAL;

                                fn = strstrip(t+8);
                                if (!path_is_absolute(fn)) {
                                        log_warning_unit(u->id,
                                                         "[%s:%u] PID file not absolute. Ignoring.",
                                                         path, line);
                                        continue;
                                }

                                if (!(fn = strdup(fn))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                free(s->pid_file);
                                s->pid_file = fn;
                        }

                } else if (state == DESCRIPTION) {

                        /* Try to parse Red Hat style description
                         * continuation */

                        size_t k = strlen(t);
                        char *j;

                        if (t[k-1] == '\\')
                                t[k-1] = 0;
                        else
                                state = NORMAL;

                        if ((j = strstrip(t)) && *j) {
                                char *d = NULL;

                                if (chkconfig_description)
                                        d = strjoin(chkconfig_description, " ", j, NULL);
                                else
                                        d = strdup(j);

                                if (!d) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                free(chkconfig_description);
                                chkconfig_description = d;
                        }

                } else if (state == LSB || state == LSB_DESCRIPTION) {

                        if (startswith_no_case(t, "Provides:")) {
                                char *i, *w;
                                size_t z;

                                state = LSB;

                                FOREACH_WORD_QUOTED(w, z, t+9, i) {
                                        char *n, *m;

                                        if (!(n = strndup(w, z))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        r = sysv_translate_facility(n, path_get_file_name(path), &m);
                                        free(n);

                                        if (r < 0)
                                                goto finish;

                                        if (r == 0)
                                                continue;

                                        if (unit_name_to_type(m) == UNIT_SERVICE)
                                                r = unit_merge_by_name(u, m);
                                        else
                                                /* NB: SysV targets
                                                 * which are provided
                                                 * by a service are
                                                 * pulled in by the
                                                 * services, as an
                                                 * indication that the
                                                 * generic service is
                                                 * now available. This
                                                 * is strictly
                                                 * one-way. The
                                                 * targets do NOT pull
                                                 * in the SysV
                                                 * services! */
                                                r = unit_add_two_dependencies_by_name(u, UNIT_BEFORE, UNIT_WANTS, m, NULL, true);

                                        if (r < 0)
                                                log_error_unit(u->id,
                                                               "[%s:%u] Failed to add LSB Provides name %s, ignoring: %s",
                                                               path, line, m, strerror(-r));

                                        free(m);
                                }

                        } else if (startswith_no_case(t, "Required-Start:") ||
                                   startswith_no_case(t, "Should-Start:") ||
                                   startswith_no_case(t, "X-Start-Before:") ||
                                   startswith_no_case(t, "X-Start-After:")) {
                                char *i, *w;
                                size_t z;

                                state = LSB;

                                FOREACH_WORD_QUOTED(w, z, strchr(t, ':')+1, i) {
                                        char *n, *m;

                                        if (!(n = strndup(w, z))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        r = sysv_translate_facility(n, path_get_file_name(path), &m);
                                        if (r < 0) {
                                                log_error_unit(u->id,
                                                               "[%s:%u] Failed to translate LSB dependency %s, ignoring: %s",
                                                               path, line, n, strerror(-r));
                                                free(n);
                                                continue;
                                        }

                                        free(n);

                                        if (r == 0)
                                                continue;

                                        if (streq(m, SPECIAL_NETWORK_ONLINE_TARGET) && !startswith_no_case(t, "X-Start-Before:"))
                                                /* the network-online target is special, as it needs to be actively pulled in */
                                                r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, m, NULL, true);
                                        else
                                                r = unit_add_dependency_by_name(u, startswith_no_case(t, "X-Start-Before:") ? UNIT_BEFORE : UNIT_AFTER, m, NULL, true);

                                        if (r < 0)
                                                log_error_unit(u->id, "[%s:%u] Failed to add dependency on %s, ignoring: %s",
                                                               path, line, m, strerror(-r));

                                        free(m);
                                }
                        } else if (startswith_no_case(t, "Default-Start:")) {
                                char *k, *d;

                                state = LSB;

                                k = delete_chars(t+14, WHITESPACE "-");

                                if (k[0] != 0) {
                                        if (!(d = strdup(k))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        free(s->sysv_runlevels);
                                        s->sysv_runlevels = d;
                                }

                        } else if (startswith_no_case(t, "Description:")) {
                                char *d, *j;

                                state = LSB_DESCRIPTION;

                                if ((j = strstrip(t+12)) && *j) {
                                        if (!(d = strdup(j))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }
                                } else
                                        d = NULL;

                                free(long_description);
                                long_description = d;

                        } else if (startswith_no_case(t, "Short-Description:")) {
                                char *d, *j;

                                state = LSB;

                                if ((j = strstrip(t+18)) && *j) {
                                        if (!(d = strdup(j))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }
                                } else
                                        d = NULL;

                                free(short_description);
                                short_description = d;

                        } else if (state == LSB_DESCRIPTION) {

                                if (startswith(l, "#\t") || startswith(l, "#  ")) {
                                        char *j;

                                        if ((j = strstrip(t)) && *j) {
                                                char *d = NULL;

                                                if (long_description)
                                                        d = strjoin(long_description, " ", t, NULL);
                                                else
                                                        d = strdup(j);

                                                if (!d) {
                                                        r = -ENOMEM;
                                                        goto finish;
                                                }

                                                free(long_description);
                                                long_description = d;
                                        }

                                } else
                                        state = LSB;
                        }
                }
        }

        if ((r = sysv_exec_commands(s, supports_reload)) < 0)
                goto finish;

        if (s->sysv_runlevels && !chars_intersect(RUNLEVELS_UP, s->sysv_runlevels)) {
                /* If there a runlevels configured for this service
                 * but none of the standard ones, then we assume this
                 * is some special kind of service (which might be
                 * needed for early boot) and don't create any links
                 * to it. */

                UNIT(s)->default_dependencies = false;

                /* Don't timeout special services during boot (like fsck) */
                s->timeout_start_usec = 0;
                s->timeout_stop_usec = 0;
        } else {
                s->timeout_start_usec = DEFAULT_SYSV_TIMEOUT_USEC;
                s->timeout_stop_usec = DEFAULT_SYSV_TIMEOUT_USEC;
        }

        /* Special setting for all SysV services */
        s->type = SERVICE_FORKING;
        s->remain_after_exit = !s->pid_file;
        s->guess_main_pid = false;
        s->restart = SERVICE_RESTART_NO;
        s->exec_context.ignore_sigpipe = false;
        s->kill_context.kill_mode = KILL_PROCESS;

        /* We use the long description only if
         * no short description is set. */

        if (short_description)
                description = short_description;
        else if (chkconfig_description)
                description = chkconfig_description;
        else if (long_description)
                description = long_description;
        else
                description = NULL;

        if (description) {
                char *d;

                if (!(d = strappend(s->sysv_has_lsb ? "LSB: " : "SYSV: ", description))) {
                        r = -ENOMEM;
                        goto finish;
                }

                u->description = d;
        }

        /* The priority that has been set in /etc/rcN.d/ hierarchies
         * takes precedence over what is stored as default in the LSB
         * header */
        if (s->sysv_start_priority_from_rcnd >= 0)
                s->sysv_start_priority = s->sysv_start_priority_from_rcnd;

        u->load_state = UNIT_LOADED;
        r = 0;

finish:

        if (f)
                fclose(f);

        free(short_description);
        free(long_description);
        free(chkconfig_description);

        return r;
}

static int service_load_sysv_name(Service *s, const char *name) {
        char **p;

        assert(s);
        assert(name);

        /* For SysV services we strip the *.sh suffixes. */
        if (endswith(name, ".sh.service"))
                return -ENOENT;

        STRV_FOREACH(p, UNIT(s)->manager->lookup_paths.sysvinit_path) {
                char *path;
                int r;

                path = strjoin(*p, "/", name, NULL);
                if (!path)
                        return -ENOMEM;

                assert(endswith(path, ".service"));
                path[strlen(path)-8] = 0;

                r = service_load_sysv_path(s, path);

                if (r >= 0 && UNIT(s)->load_state == UNIT_STUB) {
                        /* Try *.sh source'able init scripts */
                        strcat(path, ".sh");
                        r = service_load_sysv_path(s, path);
                }
                free(path);

                if (r < 0)
                        return r;

                if (UNIT(s)->load_state != UNIT_STUB)
                        break;
        }

        return 0;
}

static int service_load_sysv(Service *s) {
        const char *t;
        Iterator i;
        int r;

        assert(s);

        /* Load service data from SysV init scripts, preferably with
         * LSB headers ... */

        if (strv_isempty(UNIT(s)->manager->lookup_paths.sysvinit_path))
                return 0;

        if ((t = UNIT(s)->id))
                if ((r = service_load_sysv_name(s, t)) < 0)
                        return r;

        if (UNIT(s)->load_state == UNIT_STUB)
                SET_FOREACH(t, UNIT(s)->names, i) {
                        if (t == UNIT(s)->id)
                                continue;

                        if ((r = service_load_sysv_name(s, t)) < 0)
                                return r;

                        if (UNIT(s)->load_state != UNIT_STUB)
                                break;
                }

        return 0;
}
#endif

static int fsck_fix_order(Service *s) {
        Unit *other;
        int r;

        assert(s);

        if (s->fsck_passno <= 0)
                return 0;

        /* For each pair of services where both have an fsck priority
         * we order things based on it. */

        IWLIST_FOREACH(units_by_type, other, UNIT(s)->manager->units_by_type[UNIT_SERVICE]) {
                Service *t;
                UnitDependency d;

                t = SERVICE(other);

                if (s == t)
                        continue;

                if (UNIT(t)->load_state != UNIT_LOADED)
                        continue;

                if (t->fsck_passno <= 0)
                        continue;

                if (t->fsck_passno < s->fsck_passno)
                        d = UNIT_AFTER;
                else if (t->fsck_passno > s->fsck_passno)
                        d = UNIT_BEFORE;
                else
                        continue;

                r = unit_add_dependency(UNIT(s), d, UNIT(t), true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int service_verify(Service *s) {
        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (!s->exec_command[SERVICE_EXEC_START]) {
                log_error_unit(UNIT(s)->id,
                               "%s lacks ExecStart setting. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        if (s->type != SERVICE_ONESHOT &&
            s->exec_command[SERVICE_EXEC_START]->command_next) {
                log_error_unit(UNIT(s)->id,
                               "%s has more than one ExecStart setting, which is only allowed for Type=oneshot services. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        if (s->type == SERVICE_ONESHOT && s->restart != SERVICE_RESTART_NO) {
                log_error_unit(UNIT(s)->id,
                                "%s has Restart setting other than no, which isn't allowed for Type=oneshot services. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        if (s->type == SERVICE_DBUS && !s->bus_name) {
                log_error_unit(UNIT(s)->id,
                               "%s is of type D-Bus but no D-Bus service name has been specified. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        if (s->bus_name && s->type != SERVICE_DBUS)
                log_warning_unit(UNIT(s)->id,
                                 "%s has a D-Bus service name specified, but is not of type dbus. Ignoring.", UNIT(s)->id);

        if (s->exec_context.pam_name && s->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_error_unit(UNIT(s)->id,
                               "%s has PAM enabled. Kill mode must be set to 'control-group'. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        return 0;
}

static int service_add_default_dependencies(Service *s) {
        int r;

        assert(s);

        /* Add a number of automatic dependencies useful for the
         * majority of services. */

        /* First, pull in base system */
        if (UNIT(s)->manager->running_as == SYSTEMD_SYSTEM) {
                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES,
                                                      SPECIAL_BASIC_TARGET, NULL, true);
                if (r < 0)
                        return r;

        } else if (UNIT(s)->manager->running_as == SYSTEMD_USER) {
                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES,
                                                      SPECIAL_SOCKETS_TARGET, NULL, true);
                if (r < 0)
                        return r;

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES,
                                                      SPECIAL_TIMERS_TARGET, NULL, true);
                if (r < 0)
                        return r;

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES,
                                                      SPECIAL_PATHS_TARGET, NULL, true);
                if (r < 0)
                        return r;
        }

        /* Second, activate normal shutdown */
        r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS,
                                              SPECIAL_SHUTDOWN_TARGET, NULL, true);
        return r;
}

static void service_fix_output(Service *s) {
        assert(s);

        /* If nothing has been explicitly configured, patch default
         * output in. If input is socket/tty we avoid this however,
         * since in that case we want output to default to the same
         * place as we read input from. */

        if (s->exec_context.std_error == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_error = UNIT(s)->manager->default_std_error;

        if (s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_output = UNIT(s)->manager->default_std_output;
}

static int service_load(Unit *u) {
        int r;
        Service *s = SERVICE(u);

        assert(s);

        /* Load a .service file */
        r = unit_load_fragment(u);
        if (r < 0)
                return r;

#ifdef HAVE_SYSV_COMPAT
        /* Load a classic init script as a fallback, if we couldn't find anything */
        if (u->load_state == UNIT_STUB) {
                r = service_load_sysv(s);
                if (r < 0)
                        return r;
        }
#endif

        /* Still nothing found? Then let's give up */
        if (u->load_state == UNIT_STUB)
                return -ENOENT;

        /* This is a new unit? Then let's add in some extras */
        if (u->load_state == UNIT_LOADED) {

                /* We were able to load something, then let's add in
                 * the dropin directories. */
                r = unit_load_dropin(u);
                if (r < 0)
                        return r;

                if (s->type == _SERVICE_TYPE_INVALID)
                        s->type = s->bus_name ? SERVICE_DBUS : SERVICE_SIMPLE;

                /* Oneshot services have disabled start timeout by default */
                if (s->type == SERVICE_ONESHOT && !s->start_timeout_defined)
                        s->timeout_start_usec = 0;

                service_fix_output(s);

                r = unit_add_exec_dependencies(u, &s->exec_context);
                if (r < 0)
                        return r;

                r = unit_add_default_slice(u);
                if (r < 0)
                        return r;

#ifdef HAVE_SYSV_COMPAT
                r = sysv_fix_order(s);
                if (r < 0)
                        return r;
#endif

                r = fsck_fix_order(s);
                if (r < 0)
                        return r;

                if (s->bus_name)
                        if ((r = unit_watch_bus_name(u, s->bus_name)) < 0)
                                return r;

                if (s->type == SERVICE_NOTIFY && s->notify_access == NOTIFY_NONE)
                        s->notify_access = NOTIFY_MAIN;

                if (s->watchdog_usec > 0 && s->notify_access == NOTIFY_NONE)
                        s->notify_access = NOTIFY_MAIN;

                if (s->type == SERVICE_DBUS || s->bus_name) {
                        r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, // FIXME: was dbus_socket
                                                              SPECIAL_DBUS_SERVICE, NULL, true);
                        if (r < 0)
                                return r;
                }

                if (UNIT(s)->default_dependencies) {
                        r = service_add_default_dependencies(s);
                        if (r < 0)
                                return r;
                }

                r = unit_exec_context_defaults(u, &s->exec_context);
                if (r < 0)
                        return r;
        }

        return service_verify(s);
}

static void service_dump(Unit *u, FILE *f, const char *prefix) {

        ServiceExecCommand c;
        Service *s = SERVICE(u);
        const char *prefix2;
        _cleanup_free_ char *p2 = NULL;

        assert(s);

        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%sService State: %s\n"
                "%sResult: %s\n"
                "%sReload Result: %s\n"
                "%sPermissionsStartOnly: %s\n"
                "%sRootDirectoryStartOnly: %s\n"
                "%sRemainAfterExit: %s\n"
                "%sGuessMainPID: %s\n"
                "%sType: %s\n"
                "%sRestart: %s\n"
                "%sNotifyAccess: %s\n",
                prefix, service_state_to_string(s->state),
                prefix, service_result_to_string(s->result),
                prefix, service_result_to_string(s->reload_result),
                prefix, yes_no(s->permissions_start_only),
                prefix, yes_no(s->root_directory_start_only),
                prefix, yes_no(s->remain_after_exit),
                prefix, yes_no(s->guess_main_pid),
                prefix, service_type_to_string(s->type),
                prefix, service_restart_to_string(s->restart),
                prefix, notify_access_to_string(s->notify_access));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: %lu\n",
                        prefix, (unsigned long) s->control_pid);

        if (s->main_pid > 0)
                fprintf(f,
                        "%sMain PID: %lu\n"
                        "%sMain PID Known: %s\n"
                        "%sMain PID Alien: %s\n",
                        prefix, (unsigned long) s->main_pid,
                        prefix, yes_no(s->main_pid_known),
                        prefix, yes_no(s->main_pid_alien));

        if (s->pid_file)
                fprintf(f,
                        "%sPIDFile: %s\n",
                        prefix, s->pid_file);

        if (s->bus_name)
                fprintf(f,
                        "%sBusName: %s\n"
                        "%sBus Name Good: %s\n",
                        prefix, s->bus_name,
                        prefix, yes_no(s->bus_name_good));

        kill_context_dump(&s->kill_context, f, prefix);
        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++) {

                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s-> %s:\n",
                        prefix, service_exec_command_to_string(c));

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

#ifdef HAVE_SYSV_COMPAT
        if (s->is_sysv)
                fprintf(f,
                        "%sSysV Init Script has LSB Header: %s\n"
                        "%sSysVEnabled: %s\n",
                        prefix, yes_no(s->sysv_has_lsb),
                        prefix, yes_no(s->sysv_enabled));

        if (s->sysv_start_priority >= 0)
                fprintf(f,
                        "%sSysVStartPriority: %i\n",
                        prefix, s->sysv_start_priority);

        if (s->sysv_runlevels)
                fprintf(f, "%sSysVRunLevels: %s\n",
                        prefix, s->sysv_runlevels);
#endif

        if (s->fsck_passno > 0)
                fprintf(f,
                        "%sFsckPassNo: %i\n",
                        prefix, s->fsck_passno);

        if (s->status_text)
                fprintf(f, "%sStatus Text: %s\n",
                        prefix, s->status_text);
}

static int service_load_pid_file(Service *s, bool may_warn) {
        _cleanup_free_ char *k = NULL;
        int r;
        pid_t pid;

        assert(s);

        if (!s->pid_file)
                return -ENOENT;

        r = read_one_line_file(s->pid_file, &k);
        if (r < 0) {
                if (may_warn)
                        log_info_unit(UNIT(s)->id,
                                      "PID file %s not readable (yet?) after %s.",
                                      s->pid_file, service_state_to_string(s->state));
                return r;
        }

        r = parse_pid(k, &pid);
        if (r < 0) {
                if (may_warn)
                        log_info_unit(UNIT(s)->id,
                                      "Failed to read PID from file %s: %s",
                                      s->pid_file, strerror(-r));
                return r;
        }

        if (kill(pid, 0) < 0 && errno != EPERM) {
                if (may_warn)
                        log_info_unit(UNIT(s)->id,
                                      "PID %lu read from file %s does not exist.",
                                      (unsigned long) pid, s->pid_file);
                return -ESRCH;
        }

        r = get_process_state(pid);
        if (r < 0) {
                if (may_warn)
                        log_info_unit(UNIT(s)->id, "Failed to read /proc/%d/stat: %s",
                                      pid, strerror(-r));
                return r;
        } else if (r == 'Z') {
                if (may_warn)
                        log_info_unit(UNIT(s)->id,
                                      "PID %lu read from file %s is a zombie.",
                                      (unsigned long) pid, s->pid_file);
                return -ESRCH;
        }

        if (s->main_pid_known) {
                if (pid == s->main_pid)
                        return 0;

                log_debug_unit(UNIT(s)->id,
                               "Main PID changing: %lu -> %lu",
                               (unsigned long) s->main_pid, (unsigned long) pid);
                service_unwatch_main_pid(s);
                s->main_pid_known = false;
        } else
                log_debug_unit(UNIT(s)->id,
                               "Main PID loaded: %lu", (unsigned long) pid);

        r = service_set_main_pid(s, pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0) {
                /* FIXME: we need to do something here */
                log_warning_unit(UNIT(s)->id,
                                 "Failed to watch PID %lu from service %s",
                                 (unsigned long) pid, UNIT(s)->id);
                return r;
        }

        return 0;
}

static int service_search_main_pid(Service *s) {
        pid_t pid;
        int r;

        assert(s);

        /* If we know it anyway, don't ever fallback to unreliable
         * heuristics */
        if (s->main_pid_known)
                return 0;

        if (!s->guess_main_pid)
                return 0;

        assert(s->main_pid <= 0);

#ifdef Use_CGroups
        pid = unit_search_main_pid(UNIT(s));
#else
        unimplemented_msg("search main PID");
        pid = -1;
#endif
        if (pid <= 0)
                return -ENOENT;

        log_debug_unit(UNIT(s)->id,
                       "Main PID guessed: %lu", (unsigned long) pid);
        r = service_set_main_pid(s, pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                log_warning_unit(UNIT(s)->id,
                                 "Failed to watch PID %lu from service %s",
                                 (unsigned long) pid, UNIT(s)->id);
                return r;

        return 0;
}

static void service_set_state(Service *s, ServiceState state) {
        ServiceState old_state;
        const UnitActiveState *table;
        assert(s);

        table = s->type == SERVICE_IDLE ? state_translation_table_idle : state_translation_table;

        old_state = s->state;
        s->state = state;

        service_unwatch_pid_file(s);

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL &&
            state != SERVICE_AUTO_RESTART)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RUNNING &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL) {
                service_unwatch_main_pid(s);
                s->main_command = NULL;
        }

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL) {
                service_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
        }

        if (state == SERVICE_DEAD ||
            state == SERVICE_FAILED ||
            state == SERVICE_AUTO_RESTART)
                unit_unwatch_all_pids(UNIT(s));

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RUNNING &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL &&
            !(state == SERVICE_DEAD && UNIT(s)->job)) {
                service_close_socket_fd(s);
                service_connection_unref(s);
        }

        if (state == SERVICE_STOP || state == SERVICE_STOP_SIGTERM)
                service_stop_watchdog(s);

#ifdef Use_CGroups
        /* For the inactive states unit_notify() will trim the cgroup,
         * but for exit we have to do that ourselves... */
        if (state == SERVICE_EXITED && UNIT(s)->manager->n_reloading <= 0)
                unit_destroy_cgroup(UNIT(s));
#endif

        /* For remain_after_exit services, let's see if we can "release" the
         * hold on the console, since unit_notify() only does that in case of
         * change of state */
        if (state == SERVICE_EXITED && s->remain_after_exit &&
            UNIT(s)->manager->n_on_console > 0) {
                ExecContext *ec = unit_get_exec_context(UNIT(s));
                if (ec && exec_context_may_touch_console(ec)) {
                        Manager *m = UNIT(s)->manager;

                        m->n_on_console --;
                        if (m->n_on_console == 0)
                                /* unset no_console_output flag, since the console is free */
                                m->no_console_output = false;
                }
        }

        if (old_state != state)
                log_debug_unit(UNIT(s)->id,
                               "%s changed %s -> %s", UNIT(s)->id,
                               service_state_to_string(old_state),
                               service_state_to_string(state));

        unit_notify(UNIT(s), table[old_state], table[state], s->reload_result == SERVICE_SUCCESS);
        s->reload_result = SERVICE_SUCCESS;
}

static int service_coldplug(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(s->state == SERVICE_DEAD);

        if (s->deserialized_state != s->state) {

                if (s->deserialized_state == SERVICE_START_PRE ||
                    s->deserialized_state == SERVICE_START ||
                    s->deserialized_state == SERVICE_START_POST ||
                    s->deserialized_state == SERVICE_RELOAD ||
                    s->deserialized_state == SERVICE_STOP ||
                    s->deserialized_state == SERVICE_STOP_SIGTERM ||
                    s->deserialized_state == SERVICE_STOP_SIGKILL ||
                    s->deserialized_state == SERVICE_STOP_POST ||
                    s->deserialized_state == SERVICE_FINAL_SIGTERM ||
                    s->deserialized_state == SERVICE_FINAL_SIGKILL ||
                    s->deserialized_state == SERVICE_AUTO_RESTART) {

                        if (s->deserialized_state == SERVICE_AUTO_RESTART || s->timeout_start_usec > 0) {
                                usec_t k;

                                k = s->deserialized_state == SERVICE_AUTO_RESTART ? s->restart_usec : s->timeout_start_usec;

                                r = unit_watch_timer(UNIT(s), k, &s->timer_watch);
                                if (r < 0)
                                        return r;
                        }
                }

                if ((s->deserialized_state == SERVICE_START &&
                     (s->type == SERVICE_FORKING ||
                      s->type == SERVICE_DBUS ||
                      s->type == SERVICE_ONESHOT ||
                      s->type == SERVICE_NOTIFY)) ||
                    s->deserialized_state == SERVICE_START_POST ||
                    s->deserialized_state == SERVICE_RUNNING ||
                    s->deserialized_state == SERVICE_RELOAD ||
                    s->deserialized_state == SERVICE_STOP ||
                    s->deserialized_state == SERVICE_STOP_SIGTERM ||
                    s->deserialized_state == SERVICE_STOP_SIGKILL)
                        if (s->main_pid > 0) {
                                r = unit_watch_pid(UNIT(s), s->main_pid);
                                if (r < 0)
                                        return r;
                        }

                if (s->deserialized_state == SERVICE_START_PRE ||
                    s->deserialized_state == SERVICE_START ||
                    s->deserialized_state == SERVICE_START_POST ||
                    s->deserialized_state == SERVICE_RELOAD ||
                    s->deserialized_state == SERVICE_STOP ||
                    s->deserialized_state == SERVICE_STOP_SIGTERM ||
                    s->deserialized_state == SERVICE_STOP_SIGKILL ||
                    s->deserialized_state == SERVICE_STOP_POST ||
                    s->deserialized_state == SERVICE_FINAL_SIGTERM ||
                    s->deserialized_state == SERVICE_FINAL_SIGKILL)
                        if (s->control_pid > 0) {
                                r = unit_watch_pid(UNIT(s), s->control_pid);
                                if (r < 0)
                                        return r;
                        }

                if (s->deserialized_state != SERVICE_DEAD &&
                    s->deserialized_state != SERVICE_FAILED &&
                    s->deserialized_state != SERVICE_AUTO_RESTART)
                        unit_watch_all_pids(UNIT(s));

                if (s->deserialized_state == SERVICE_START_POST ||
                    s->deserialized_state == SERVICE_RUNNING ||
                    s->deserialized_state == SERVICE_RELOAD)
                        service_handle_watchdog(s);

                service_set_state(s, s->deserialized_state);
        }
        return 0;
}

static int service_collect_fds(Service *s, int **fds, unsigned *n_fds) {
        Iterator i;
        int r;
        int *rfds = NULL;
        unsigned rn_fds = 0;
        Unit *u;

        assert(s);
        assert(fds);
        assert(n_fds);

        if (s->socket_fd >= 0)
                return 0;

        SET_FOREACH(u, UNIT(s)->dependencies[UNIT_TRIGGERED_BY], i) {
                int *cfds;
                unsigned cn_fds;
                Socket *sock;

                if (u->type != UNIT_SOCKET)
                        continue;

                sock = SOCKET(u);

                r = socket_collect_fds(sock, &cfds, &cn_fds);
                if (r < 0)
                        goto fail;

                if (!cfds)
                        continue;

                if (!rfds) {
                        rfds = cfds;
                        rn_fds = cn_fds;
                } else {
                        int *t;

                        t = new(int, rn_fds+cn_fds);
                        if (!t) {
                                free(cfds);
                                r = -ENOMEM;
                                goto fail;
                        }

                        memcpy(t, rfds, rn_fds * sizeof(int));
                        memcpy(t+rn_fds, cfds, cn_fds * sizeof(int));
                        free(rfds);
                        free(cfds);

                        rfds = t;
                        rn_fds = rn_fds+cn_fds;
                }
        }

        *fds = rfds;
        *n_fds = rn_fds;

        return 0;

fail:
        free(rfds);

        return r;
}

static int service_spawn(
                Service *s,
                ExecCommand *c,
                bool timeout,
                bool pass_fds,
                bool apply_permissions,
                bool apply_chroot,
                bool apply_tty_stdin,
                bool set_notify_socket,
                bool is_control,
                pid_t *_pid) {

        pid_t pid;
        int r;
        int *fds = NULL;
        _cleanup_free_ int *fdsbuf = NULL;
        unsigned n_fds = 0, n_env = 0;
        _cleanup_strv_free_ char
                **argv = NULL, **final_env = NULL, **our_env = NULL;
        const char *path;

        assert(s);
        assert(c);
        assert(_pid);

#ifdef Use_CGroup
        unit_realize_cgroup(UNIT(s));
#elif defined(Use_PTGroups)
        unit_realize_ptgroup(UNIT(s));
#endif

        if (pass_fds ||
            s->exec_context.std_input == EXEC_INPUT_SOCKET ||
            s->exec_context.std_output == EXEC_OUTPUT_SOCKET ||
            s->exec_context.std_error == EXEC_OUTPUT_SOCKET) {

                if (s->socket_fd >= 0) {
                        fds = &s->socket_fd;
                        n_fds = 1;
                } else {
                        r = service_collect_fds(s, &fdsbuf, &n_fds);
                        if (r < 0)
                                goto fail;

                        fds = fdsbuf;
                }
        }

        if (timeout && s->timeout_start_usec) {
                r = unit_watch_timer(UNIT(s), s->timeout_start_usec, &s->timer_watch);
                if (r < 0)
                        goto fail;
        } else
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        r = unit_full_printf_strv(UNIT(s), c->argv, &argv);
        if (r < 0)
                goto fail;

        our_env = new0(char*, 5);
        if (!our_env) {
                r = -ENOMEM;
                goto fail;
        }

        if (set_notify_socket)
                if (asprintf(our_env + n_env++, "NOTIFY_SOCKET=%s", UNIT(s)->manager->notify_socket) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (s->main_pid > 0)
                if (asprintf(our_env + n_env++, "MAINPID=%lu", (unsigned long) s->main_pid) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (s->watchdog_usec > 0)
                if (asprintf(our_env + n_env++, "WATCHDOG_USEC=%llu", (unsigned long long) s->watchdog_usec) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (UNIT(s)->manager->running_as != SYSTEMD_SYSTEM)
                if (asprintf(our_env + n_env++, "MANAGERPID=%lu", (unsigned long) getpid()) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        final_env = strv_env_merge(2, UNIT(s)->manager->environment, our_env, NULL);
        if (!final_env) {
                r = -ENOMEM;
                goto fail;
        }

#ifdef Use_CGroups /* FIXME: PTGroups adaptation */
        if (is_control && UNIT(s)->cgroup_path) {
                path = strappenda(UNIT(s)->cgroup_path, "/control");
                cg_create(SYSTEMD_CGROUP_CONTROLLER, path);
        } else
                path = UNIT(s)->cgroup_path;
#endif

        r = exec_spawn(c,
                       argv,
                       &s->exec_context,
                       fds, n_fds,
                       final_env,
                       apply_permissions,
                       apply_chroot,
                       apply_tty_stdin,
                       UNIT(s)->manager->confirm_spawn,
#ifdef Use_CGroups
                       UNIT(s)->manager->cgroup_supported,
                       path,
#elif defined(Use_PTGroups)
                UNIT(s)->manager->pt_manager,
                UNIT(s)->ptgroup,
#endif
                       UNIT(s)->id,
                       s->type == SERVICE_IDLE ? UNIT(s)->manager->idle_pipe : NULL,
                       &pid);
        if (r < 0)
                goto fail;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        if (timeout)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, 1 if it is good, -1 if we
         * don't know */

        /* If we know the pid file, then lets just check if it is
         * still valid */
        if (s->main_pid_known) {

                /* If it's an alien child let's check if it is still
                 * alive ... */
                if (s->main_pid_alien && s->main_pid > 0)
                        return kill(s->main_pid, 0) >= 0 || errno != ESRCH;

                /* .. otherwise assume we'll get a SIGCHLD for it,
                 * which we really should wait for to collect exit
                 * status and code */
                return s->main_pid > 0;
        }

        /* We don't know the pid */
        return -EAGAIN;
}

_pure_ static int control_pid_good(Service *s) {
        assert(s);

        return s->control_pid > 0;
}

static int cgroup_good(Service *s) {
#ifdef Use_CGroups
        int r;

        assert(s);

        if (!UNIT(s)->cgroup_path)
                return 0;

        r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, UNIT(s)->cgroup_path, true);
        if (r < 0)
                return r;

        return !r;
#elif defined(Use_PTGroups)
        assert(s);

        if (!UNIT(s)->ptgroup)
                return 0;

        return !ptg_is_empty_recursive(UNIT(s)->ptgroup);
#else
        unimplemented();
        return true;
#endif
}

static void service_enter_dead(Service *s, ServiceResult f, bool allow_restart) {
        int r;
        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_set_state(s, s->result != SERVICE_SUCCESS ? SERVICE_FAILED : SERVICE_DEAD);

        if (allow_restart &&
            !s->forbid_restart &&
            (s->restart == SERVICE_RESTART_ALWAYS ||
             (s->restart == SERVICE_RESTART_ON_SUCCESS && s->result == SERVICE_SUCCESS) ||
             (s->restart == SERVICE_RESTART_ON_FAILURE && s->result != SERVICE_SUCCESS) ||
             (s->restart == SERVICE_RESTART_ON_WATCHDOG && s->result == SERVICE_FAILURE_WATCHDOG) ||
             (s->restart == SERVICE_RESTART_ON_ABORT && (s->result == SERVICE_FAILURE_SIGNAL ||
                                                         s->result == SERVICE_FAILURE_CORE_DUMP))) &&
            (s->result != SERVICE_FAILURE_EXIT_CODE ||
             !set_contains(s->restart_ignore_status.code, INT_TO_PTR(s->main_exec_status.status))) &&
            (s->result != SERVICE_FAILURE_SIGNAL ||
             !set_contains(s->restart_ignore_status.signal, INT_TO_PTR(s->main_exec_status.status)))
                ) {

                r = unit_watch_timer(UNIT(s), s->restart_usec, &s->timer_watch);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_AUTO_RESTART);
        }

        s->forbid_restart = false;

        /* we want fresh tmpdirs in case service is started again immediately */
        exec_context_tmp_dirs_done(&s->exec_context);

        /* Try to delete the pid file. At this point it will be
         * out-of-date, and some software might be confused by it, so
         * let's remove it. */
        if (s->pid_file)
                unlink_noerrno(s->pid_file);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run install restart timer: %s",
                         UNIT(s)->id, strerror(-r));
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void service_enter_stop_post(Service *s, ServiceResult f) {
        int r;
        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        unit_watch_all_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP_POST;

                r = service_spawn(s,
                                  s->control_command,
                                  true,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  true,
                                  false,
                                  true,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;


                service_set_state(s, SERVICE_STOP_POST);
        } else
                service_enter_dead(s, SERVICE_SUCCESS, true);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'stop-post' task: %s",
                         UNIT(s)->id, strerror(-r));
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_enter_signal(Service *s, ServiceState state, ServiceResult f) {
        int r;

        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        unit_watch_all_pids(UNIT(s));

        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        state != SERVICE_STOP_SIGTERM && state != SERVICE_FINAL_SIGTERM,
                        s->main_pid,
                        s->control_pid,
                        s->main_pid_alien);
        if (r < 0)
                goto fail;

        if (r > 0) {
                if (s->timeout_stop_usec > 0) {
                        r = unit_watch_timer(UNIT(s), s->timeout_stop_usec, &s->timer_watch);
                        if (r < 0)
                                goto fail;
                }

                service_set_state(s, state);
        } else if (state == SERVICE_STOP_SIGTERM || state == SERVICE_STOP_SIGKILL)
                service_enter_stop_post(s, SERVICE_SUCCESS);
        else
                service_enter_dead(s, SERVICE_SUCCESS, true);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to kill processes: %s", UNIT(s)->id, strerror(-r));

        if (state == SERVICE_STOP_SIGTERM || state == SERVICE_STOP_SIGKILL)
                service_enter_stop_post(s, SERVICE_FAILURE_RESOURCES);
        else
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void service_enter_stop(Service *s, ServiceResult f) {
        int r;

        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        unit_watch_all_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP;

                r = service_spawn(s,
                                  s->control_command,
                                  true,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  false,
                                  true,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_STOP);
        } else
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'stop' task: %s", UNIT(s)->id, strerror(-r));
        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_enter_running(Service *s, ServiceResult f) {
        int main_pid_ok, cgroup_ok;
        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        main_pid_ok = main_pid_good(s);
        cgroup_ok = cgroup_good(s);

        if ((main_pid_ok > 0 || (main_pid_ok < 0 && cgroup_ok != 0)) &&
            (s->bus_name_good || s->type != SERVICE_DBUS))
                service_set_state(s, SERVICE_RUNNING);
        else if (s->remain_after_exit)
                service_set_state(s, SERVICE_EXITED);
        else
                service_enter_stop(s, SERVICE_SUCCESS);
}

static void service_enter_start_post(Service *s) {
        int r;
        assert(s);

        service_unwatch_control_pid(s);

        if (s->watchdog_usec > 0)
                service_reset_watchdog(s);

        s->control_command = s->exec_command[SERVICE_EXEC_START_POST];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_START_POST;

                r = service_spawn(s,
                                  s->control_command,
                                  true,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  false,
                                  true,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_POST);
        } else
                service_enter_running(s, SERVICE_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'start-post' task: %s", UNIT(s)->id, strerror(-r));
        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void service_kill_control_processes(Service *s) {
#ifdef Use_CGroups
        char *p;

        if (!UNIT(s)->cgroup_path)
                return;

        p = strappenda(UNIT(s)->cgroup_path, "/control");
        cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, p, SIGKILL, true, true, true, NULL);
#else
        unimplemented();
#endif
}

static void service_enter_start(Service *s) {
        ExecCommand *c;
        pid_t pid;
        int r;

        assert(s);

        assert(s->exec_command[SERVICE_EXEC_START]);
        assert(!s->exec_command[SERVICE_EXEC_START]->command_next || s->type == SERVICE_ONESHOT);

        service_unwatch_control_pid(s);
        service_unwatch_main_pid(s);

        /* We want to ensure that nobody leaks processes from
         * START_PRE here, so let's go on a killing spree, People
         * should not spawn long running processes from START_PRE. */
        service_kill_control_processes(s);

        if (s->type == SERVICE_FORKING) {
                s->control_command_id = SERVICE_EXEC_START;
                c = s->control_command = s->exec_command[SERVICE_EXEC_START];

                s->main_command = NULL;
        } else {
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
                s->control_command = NULL;

                c = s->main_command = s->exec_command[SERVICE_EXEC_START];
        }

        r = service_spawn(s,
                          c,
                          s->type == SERVICE_FORKING || s->type == SERVICE_DBUS ||
                            s->type == SERVICE_NOTIFY || s->type == SERVICE_ONESHOT,
                          true,
                          true,
                          true,
                          true,
                          s->notify_access != NOTIFY_NONE,
                          false,
                          &pid);
        if (r < 0)
                goto fail;

        if (s->type == SERVICE_SIMPLE || s->type == SERVICE_IDLE) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                service_set_main_pid(s, pid);
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                s->control_pid = pid;
                service_set_state(s, SERVICE_START);

        } else if (s->type == SERVICE_ONESHOT ||
                   s->type == SERVICE_DBUS ||
                   s->type == SERVICE_NOTIFY) {

                /* For oneshot services we wait until the start
                 * process exited, too, but it is our main process. */

                /* For D-Bus services we know the main pid right away,
                 * but wait for the bus name to appear on the
                 * bus. Notify services are similar. */

                service_set_main_pid(s, pid);
                service_set_state(s, SERVICE_START);
        } else
                assert_not_reached("Unknown service type");

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'start' task: %s", UNIT(s)->id, strerror(-r));
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_enter_start_pre(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_START_PRE];
        if (s->control_command) {
                /* Before we start anything, let's clear up what might
                 * be left from previous runs. */
                service_kill_control_processes(s);

                s->control_command_id = SERVICE_EXEC_START_PRE;

                r = service_spawn(s,
                                  s->control_command,
                                  true,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  true,
                                  false,
                                  true,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_PRE);
        } else
                service_enter_start(s);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'start-pre' task: %s", UNIT(s)->id, strerror(-r));
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void service_enter_restart(Service *s) {
        int r;
        DBusError error;

        assert(s);
        dbus_error_init(&error);

        if (UNIT(s)->job && UNIT(s)->job->type == JOB_STOP) {
                /* Don't restart things if we are going down anyway */
                log_info_unit(UNIT(s)->id,
                              "Stop job pending for unit, delaying automatic restart.");

                r = unit_watch_timer(UNIT(s), s->restart_usec, &s->timer_watch);
                if (r < 0)
                        goto fail;

                return;
        }

        /* Any units that are bound to this service must also be
         * restarted. We use JOB_RESTART (instead of the more obvious
         * JOB_START) here so that those dependency jobs will be added
         * as well. */
        r = manager_add_job(UNIT(s)->manager, JOB_RESTART, UNIT(s), JOB_FAIL, false, &error, NULL);
        if (r < 0)
                goto fail;

        /* Note that we stay in the SERVICE_AUTO_RESTART state here,
         * it will be canceled as part of the service_stop() call that
         * is executed as part of JOB_RESTART. */

        log_debug_unit(UNIT(s)->id,
                       "%s scheduled restart job.", UNIT(s)->id);
        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to schedule restart job: %s",
                         UNIT(s)->id, bus_error(&error, -r));
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);

        dbus_error_free(&error);
}

static void service_enter_reload(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_RELOAD];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_RELOAD;

                r = service_spawn(s,
                                  s->control_command,
                                  true,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  false,
                                  true,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_RELOAD);
        } else
                service_enter_running(s, SERVICE_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'reload' task: %s",
                         UNIT(s)->id, strerror(-r));
        s->reload_result = SERVICE_FAILURE_RESOURCES;
        service_enter_running(s, SERVICE_SUCCESS);
}

static void service_run_next_control(Service *s) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        assert(s->control_command_id != SERVICE_EXEC_START);

        s->control_command = s->control_command->command_next;
        service_unwatch_control_pid(s);

        r = service_spawn(s,
                          s->control_command,
                          true,
                          false,
                          !s->permissions_start_only,
                          !s->root_directory_start_only,
                          s->control_command_id == SERVICE_EXEC_START_PRE ||
                          s->control_command_id == SERVICE_EXEC_STOP_POST,
                          false,
                          true,
                          &s->control_pid);
        if (r < 0)
                goto fail;

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run next control task: %s",
                         UNIT(s)->id, strerror(-r));

        if (s->state == SERVICE_START_PRE)
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
        else if (s->state == SERVICE_STOP)
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
        else if (s->state == SERVICE_STOP_POST)
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
        else if (s->state == SERVICE_RELOAD) {
                s->reload_result = SERVICE_FAILURE_RESOURCES;
                service_enter_running(s, SERVICE_SUCCESS);
        } else
                service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void service_run_next_main(Service *s) {
        pid_t pid;
        int r;

        assert(s);
        assert(s->main_command);
        assert(s->main_command->command_next);
        assert(s->type == SERVICE_ONESHOT);

        s->main_command = s->main_command->command_next;
        service_unwatch_main_pid(s);

        r = service_spawn(s,
                          s->main_command,
                          true,
                          true,
                          true,
                          true,
                          true,
                          s->notify_access != NOTIFY_NONE,
                          false,
                          &pid);
        if (r < 0)
                goto fail;

        service_set_main_pid(s, pid);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run next main task: %s", UNIT(s)->id, strerror(-r));
        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static int service_start_limit_test(Service *s) {
        assert(s);

        if (ratelimit_test(&s->start_limit))
                return 0;

        switch (s->start_limit_action) {

        case SERVICE_START_LIMIT_NONE:
                log_warning_unit(UNIT(s)->id,
                                 "%s start request repeated too quickly, refusing to start.",
                                 UNIT(s)->id);
                break;

        case SERVICE_START_LIMIT_REBOOT: {
                DBusError error;
                int r;

                dbus_error_init(&error);

                log_warning_unit(UNIT(s)->id,
                                 "%s start request repeated too quickly, rebooting.", UNIT(s)->id);

                r = manager_add_job_by_name(UNIT(s)->manager, JOB_START,
                                            SPECIAL_REBOOT_TARGET, JOB_REPLACE,
                                            true, &error, NULL);
                if (r < 0) {
                        log_error_unit(UNIT(s)->id,
                                       "Failed to reboot: %s.", bus_error(&error, r));
                        dbus_error_free(&error);
                }

                break;
        }

        case SERVICE_START_LIMIT_REBOOT_FORCE:
                log_warning_unit(UNIT(s)->id,
                                 "%s start request repeated too quickly, forcibly rebooting.", UNIT(s)->id);
                UNIT(s)->manager->exit_code = MANAGER_REBOOT;
                break;

        case SERVICE_START_LIMIT_REBOOT_IMMEDIATE:
                log_warning_unit(UNIT(s)->id,
                                 "%s start request repeated too quickly, rebooting immediately.", UNIT(s)->id);
                sync();
                reboot(RB_AUTOBOOT);
                break;

        default:
                log_error_unit(UNIT(s)->id,
                               "start limit action=%i", s->start_limit_action);
                assert_not_reached("Unknown StartLimitAction.");
        }

        return -ECANCELED;
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (s->state == SERVICE_STOP ||
            s->state == SERVICE_STOP_SIGTERM ||
            s->state == SERVICE_STOP_SIGKILL ||
            s->state == SERVICE_STOP_POST ||
            s->state == SERVICE_FINAL_SIGTERM ||
            s->state == SERVICE_FINAL_SIGKILL)
                return -EAGAIN;

        /* Already on it! */
        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST)
                return 0;

        /* A service that will be restarted must be stopped first to
         * trigger BindsTo and/or OnFailure dependencies. If a user
         * does not want to wait for the holdoff time to elapse, the
         * service should be manually restarted, not started. We
         * simply return EAGAIN here, so that any start jobs stay
         * queued, and assume that the auto restart timer will
         * eventually trigger the restart. */
        if (s->state == SERVICE_AUTO_RESTART)
                return -EAGAIN;

        assert(s->state == SERVICE_DEAD || s->state == SERVICE_FAILED);

        /* Make sure we don't enter a busy loop of some kind. */
        r = service_start_limit_test(s);
        if (r < 0) {
                service_enter_dead(s, SERVICE_FAILURE_START_LIMIT, false);
                return r;
        }

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;
        s->main_pid_known = false;
        s->main_pid_alien = false;
        s->forbid_restart = false;

        free(s->status_text);
        s->status_text = NULL;

        service_enter_start_pre(s);
        return 0;
}

static int service_stop(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Don't create restart jobs from here. */
        s->forbid_restart = true;

        /* Already on it */
        if (s->state == SERVICE_STOP ||
            s->state == SERVICE_STOP_SIGTERM ||
            s->state == SERVICE_STOP_SIGKILL ||
            s->state == SERVICE_STOP_POST ||
            s->state == SERVICE_FINAL_SIGTERM ||
            s->state == SERVICE_FINAL_SIGKILL)
                return 0;

        /* A restart will be scheduled or is in progress. */
        if (s->state == SERVICE_AUTO_RESTART) {
                service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        /* If there's already something running we go directly into
         * kill mode. */
        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST ||
            s->state == SERVICE_RELOAD) {
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
                return 0;
        }

        assert(s->state == SERVICE_RUNNING ||
               s->state == SERVICE_EXITED);

        service_enter_stop(s, SERVICE_SUCCESS);
        return 0;
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(s->state == SERVICE_RUNNING || s->state == SERVICE_EXITED);

        service_enter_reload(s);
        return 0;
}

_pure_ static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static int service_serialize(Unit *u, FILE *f, FDSet *fds) {
        Service *s = SERVICE(u);

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", service_state_to_string(s->state));
        unit_serialize_item(u, f, "result", service_result_to_string(s->result));
        unit_serialize_item(u, f, "reload-result", service_result_to_string(s->reload_result));

        if (s->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", "%lu",
                                           (unsigned long) s->control_pid);

        if (s->main_pid_known && s->main_pid > 0)
                unit_serialize_item_format(u, f, "main-pid", "%lu", (unsigned long) s->main_pid);

        unit_serialize_item(u, f, "main-pid-known", yes_no(s->main_pid_known));

        if (s->status_text)
                unit_serialize_item(u, f, "status-text", s->status_text);

        /* FIXME: There's a minor uncleanliness here: if there are
         * multiple commands attached here, we will start from the
         * first one again */
        if (s->control_command_id >= 0)
                unit_serialize_item(u, f, "control-command",
                                    service_exec_command_to_string(s->control_command_id));

        if (s->socket_fd >= 0) {
                int copy;

                if ((copy = fdset_put_dup(fds, s->socket_fd)) < 0)
                        return copy;

                unit_serialize_item_format(u, f, "socket-fd", "%i", copy);
        }

        if (s->main_exec_status.pid > 0) {
                unit_serialize_item_format(u, f, "main-exec-status-pid", "%lu",
                                           (unsigned long) s->main_exec_status.pid);
                dual_timestamp_serialize(f, "main-exec-status-start",
                                         &s->main_exec_status.start_timestamp);
                dual_timestamp_serialize(f, "main-exec-status-exit",
                                         &s->main_exec_status.exit_timestamp);

                if (dual_timestamp_is_set(&s->main_exec_status.exit_timestamp)) {
                        unit_serialize_item_format(u, f, "main-exec-status-code", "%i",
                                                   s->main_exec_status.code);
                        unit_serialize_item_format(u, f, "main-exec-status-status", "%i",
                                                   s->main_exec_status.status);
                }
        }
        if (dual_timestamp_is_set(&s->watchdog_timestamp))
                dual_timestamp_serialize(f, "watchdog-timestamp",
                                         &s->watchdog_timestamp);

        if (s->exec_context.tmp_dir)
                unit_serialize_item(u, f, "tmp-dir", s->exec_context.tmp_dir);

        if (s->exec_context.var_tmp_dir)
                unit_serialize_item(u, f, "var-tmp-dir", s->exec_context.var_tmp_dir);

        if (s->forbid_restart)
                unit_serialize_item(u, f, "forbid-restart", yes_no(s->forbid_restart));

        return 0;
}

static int service_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Service *s = SERVICE(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                ServiceState state;

                state = service_state_from_string(value);
                if (state < 0)
                        log_debug_unit(u->id, "Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "result")) {
                ServiceResult f;

                f = service_result_from_string(value);
                if (f < 0)
                        log_debug_unit(u->id, "Failed to parse result value %s", value);
                else if (f != SERVICE_SUCCESS)
                        s->result = f;

        } else if (streq(key, "reload-result")) {
                ServiceResult f;

                f = service_result_from_string(value);
                if (f < 0)
                        log_debug_unit(u->id, "Failed to parse reload result value %s", value);
                else if (f != SERVICE_SUCCESS)
                        s->reload_result = f;

        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug_unit(u->id, "Failed to parse control-pid value %s", value);
                else
                        s->control_pid = pid;
        } else if (streq(key, "main-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug_unit(u->id, "Failed to parse main-pid value %s", value);
                else {
                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid);
                }
        } else if (streq(key, "main-pid-known")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_debug_unit(u->id, "Failed to parse main-pid-known value %s", value);
                else
                        s->main_pid_known = b;
        } else if (streq(key, "status-text")) {
                char *t;

                t = strdup(value);
                if (!t)
                        log_oom();
                else {
                        free(s->status_text);
                        s->status_text = t;
                }

        } else if (streq(key, "control-command")) {
                ServiceExecCommand id;

                id = service_exec_command_from_string(value);
                if (id < 0)
                        log_debug_unit(u->id, "Failed to parse exec-command value %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command[id];
                }
        } else if (streq(key, "socket-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_debug_unit(u->id, "Failed to parse socket-fd value %s", value);
                else {

                        asynchronous_close(s->socket_fd);
                        s->socket_fd = fdset_remove(fds, fd);
                }
        } else if (streq(key, "main-exec-status-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug_unit(u->id, "Failed to parse main-exec-status-pid value %s", value);
                else
                        s->main_exec_status.pid = pid;
        } else if (streq(key, "main-exec-status-code")) {
                int i;

                if (safe_atoi(value, &i) < 0)
                        log_debug_unit(u->id, "Failed to parse main-exec-status-code value %s", value);
                else
                        s->main_exec_status.code = i;
        } else if (streq(key, "main-exec-status-status")) {
                int i;

                if (safe_atoi(value, &i) < 0)
                        log_debug_unit(u->id, "Failed to parse main-exec-status-status value %s", value);
                else
                        s->main_exec_status.status = i;
        } else if (streq(key, "main-exec-status-start"))
                dual_timestamp_deserialize(value, &s->main_exec_status.start_timestamp);
        else if (streq(key, "main-exec-status-exit"))
                dual_timestamp_deserialize(value, &s->main_exec_status.exit_timestamp);
        else if (streq(key, "watchdog-timestamp"))
                dual_timestamp_deserialize(value, &s->watchdog_timestamp);
        else if (streq(key, "tmp-dir")) {
                char *t;

                t = strdup(value);
                if (!t)
                        return log_oom();

                s->exec_context.tmp_dir = t;
        } else if (streq(key, "var-tmp-dir")) {
                char *t;

                t = strdup(value);
                if (!t)
                        return log_oom();

                s->exec_context.var_tmp_dir = t;
        } else if (streq(key, "forbid-restart")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_debug_unit(u->id, "Failed to parse forbid-restart value %s", value);
                else
                        s->forbid_restart = b;
        } else
                log_debug_unit(u->id, "Unknown serialization key '%s'", key);

        return 0;
}

_pure_ static UnitActiveState service_active_state(Unit *u) {
        const UnitActiveState *table;

        assert(u);

        table = SERVICE(u)->type == SERVICE_IDLE ? state_translation_table_idle : state_translation_table;

        return table[SERVICE(u)->state];
}

static const char *service_sub_state_to_string(Unit *u) {
        assert(u);

        return service_state_to_string(SERVICE(u)->state);
}

static bool service_check_gc(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Never clean up services that still have a process around,
         * even if the service is formally dead. */
        if (cgroup_good(s) > 0 ||
            main_pid_good(s) > 0 ||
            control_pid_good(s) > 0)
                return true;

#ifdef HAVE_SYSV_COMPAT
        if (s->is_sysv)
                return true;
#endif

        return false;
}

_pure_ static bool service_check_snapshot(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !s->got_socket_fd;
}

static int service_retry_pid_file(Service *s) {
        int r;

        assert(s->pid_file);
        assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);

        r = service_load_pid_file(s, false);
        if (r < 0)
                return r;

        service_unwatch_pid_file(s);

        service_enter_running(s, SERVICE_SUCCESS);
        return 0;
}

static int service_watch_pid_file(Service *s) {
        int r;

        log_debug_unit(UNIT(s)->id,
                       "Setting watch for %s's PID file %s",
                       UNIT(s)->id, s->pid_file_pathspec->path);
        r = path_spec_watch(s->pid_file_pathspec, UNIT(s));
        if (r < 0)
                goto fail;

        /* the pidfile might have appeared just before we set the watch */
        log_debug_unit(UNIT(s)->id,
                       "Trying to read %s's PID file %s in case it changed",
                       UNIT(s)->id, s->pid_file_pathspec->path);
        service_retry_pid_file(s);

        return 0;
fail:
        log_error_unit(UNIT(s)->id,
                       "Failed to set a watch for %s's PID file %s: %s",
                       UNIT(s)->id, s->pid_file_pathspec->path, strerror(-r));
        service_unwatch_pid_file(s);
        return r;
}

static int service_demand_pid_file(Service *s) {
        PathSpec *ps;

        assert(s->pid_file);
        assert(!s->pid_file_pathspec);

        ps = new0(PathSpec, 1);
        if (!ps)
                return -ENOMEM;

        ps->path = strdup(s->pid_file);
        if (!ps->path) {
                free(ps);
                return -ENOMEM;
        }

        path_kill_slashes(ps->path);

        /* PATH_CHANGED would not be enough. There are daemons (sendmail) that
         * keep their PID file open all the time. */
        ps->type = PATH_MODIFIED;
        ps->inotify_fd = -1;

        s->pid_file_pathspec = ps;

        return service_watch_pid_file(s);
}

static void service_fd_event(Unit *u, int fd, int revents, ev_io *w)
{
        Service *s = SERVICE(u);

        assert(s);
        assert(fd >= 0);
        assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);
        assert(s->pid_file_pathspec);
        assert(path_spec_owns_inotify_fd(s->pid_file_pathspec, fd));

        log_debug_unit(u->id, "inotify event for %s", u->id);

        if (path_spec_fd_event(s->pid_file_pathspec, revents) < 0)
                goto fail;

        if (service_retry_pid_file(s) == 0)
                return;

        if (service_watch_pid_file(s) < 0)
                goto fail;

        return;
fail:
        service_unwatch_pid_file(s);
        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_notify_cgroup_empty_event(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);

        log_debug_unit(u->id, "%s: cgroup is empty", u->id);

        switch (s->state) {

                /* Waiting for SIGCHLD is usually more interesting,
                 * because it includes return codes/signals. Which is
                 * why we ignore the cgroup events for most cases,
                 * except when we don't know pid which to expect the
                 * SIGCHLD for. */

        case SERVICE_START:
        case SERVICE_START_POST:
                /* If we were hoping for the daemon to write its PID file,
                 * we can give up now. */
                if (s->pid_file_pathspec) {
                        log_warning_unit(u->id,
                                         "%s never wrote its PID file. Failing.", UNIT(s)->id);
                        service_unwatch_pid_file(s);
                        if (s->state == SERVICE_START)
                                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
                        else
                                service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                }
                break;

        case SERVICE_RUNNING:
                /* service_enter_running() will figure out what to do */
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:

                if (main_pid_good(s) <= 0 && !control_pid_good(s))
                        service_enter_stop_post(s, SERVICE_SUCCESS);

                break;

        case SERVICE_STOP_POST:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                if (main_pid_good(s) <= 0 && !control_pid_good(s))
                        service_enter_dead(s, SERVICE_SUCCESS, true);

                break;

        default:
                ;
        }
}

static void service_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Service *s = SERVICE(u);
        ServiceResult f;

        assert(s);
        assert(pid >= 0);

        if (UNIT(s)->fragment_path ? is_clean_exit(code, status, &s->success_status) :
                                     is_clean_exit_lsb(code, status, &s->success_status))
                f = SERVICE_SUCCESS;
        else if (code == CLD_EXITED)
                f = SERVICE_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SERVICE_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SERVICE_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown code");

        if (s->main_pid == pid) {
                /* Forking services may occasionally move to a new PID.
                 * As long as they update the PID file before exiting the old
                 * PID, they're fine. */
                if (service_load_pid_file(s, false) == 0)
                        return;

                s->main_pid = 0;
                exec_status_exit(&s->main_exec_status, &s->exec_context, pid, code, status);

                if (s->main_command) {
                        /* If this is not a forking service than the
                         * main process got started and hence we copy
                         * the exit status so that it is recorded both
                         * as main and as control process exit
                         * status */

                        s->main_command->exec_status = s->main_exec_status;

                        if (s->main_command->ignore)
                                f = SERVICE_SUCCESS;
                } else if (s->exec_command[SERVICE_EXEC_START]) {

                        /* If this is a forked process, then we should
                         * ignore the return value if this was
                         * configured for the starter process */

                        if (s->exec_command[SERVICE_EXEC_START]->ignore)
                                f = SERVICE_SUCCESS;
                }

                log_struct_unit(f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
                           u->id,
                           "MESSAGE=%s: main process exited, code=%s, status=%i/%s",
                                  u->id, sigchld_code_to_string(code), status,
                                  strna(code == CLD_EXITED
                                        ? exit_status_to_string(status, EXIT_STATUS_FULL)
                                        : signal_to_string(status)),
                           "EXIT_CODE=%s", sigchld_code_to_string(code),
                           "EXIT_STATUS=%i", status,
                           NULL);

                if (f != SERVICE_SUCCESS)
                        s->result = f;

                if (s->main_command &&
                    s->main_command->command_next &&
                    f == SERVICE_SUCCESS) {

                        /* There is another command to *
                         * execute, so let's do that. */

                        log_debug_unit(u->id,
                                       "%s running next main command for state %s",
                                       u->id, service_state_to_string(s->state));
                        service_run_next_main(s);

                } else {

                        /* The service exited, so the service is officially
                         * gone. */
                        s->main_command = NULL;

                        switch (s->state) {

                        case SERVICE_START_POST:
                        case SERVICE_RELOAD:
                        case SERVICE_STOP:
                                /* Need to wait until the operation is
                                 * done */
                                break;

                        case SERVICE_START:
                                if (s->type == SERVICE_ONESHOT) {
                                        /* This was our main goal, so let's go on */
                                        if (f == SERVICE_SUCCESS)
                                                service_enter_start_post(s);
                                        else
                                                service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                        break;
                                }

                                /* Fall through */

                        case SERVICE_RUNNING:
                                service_enter_running(s, f);
                                break;

                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:

                                if (!control_pid_good(s))
                                        service_enter_stop_post(s, f);

                                /* If there is still a control process, wait for that first */
                                break;

                        default:
                                assert_not_reached("Uh, main process died at wrong time.");
                        }
                }

        } else if (s->control_pid == pid) {
                s->control_pid = 0;

                if (s->control_command) {
                        exec_status_exit(&s->control_command->exec_status,
                                         &s->exec_context, pid, code, status);

                        if (s->control_command->ignore)
                                f = SERVICE_SUCCESS;
                }

                log_full_unit(f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE, u->id,
                              "%s: control process exited, code=%s status=%i",
                              u->id, sigchld_code_to_string(code), status);

                if (f != SERVICE_SUCCESS)
                        s->result = f;

                /* Immediately get rid of the cgroup, so that the
                 * kernel doesn't delay the cgroup empty messages for
                 * the service cgroup any longer than necessary */
                service_kill_control_processes(s);

                if (s->control_command &&
                    s->control_command->command_next &&
                    f == SERVICE_SUCCESS) {

                        /* There is another command to *
                         * execute, so let's do that. */

                        log_debug_unit(u->id,
                                       "%s running next control command for state %s",
                                       u->id, service_state_to_string(s->state));
                        service_run_next_control(s);

                } else {
                        /* No further commands for this step, so let's
                         * figure out what to do next */

                        s->control_command = NULL;
                        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

                        log_debug_unit(u->id,
                                       "%s got final SIGCHLD for state %s",
                                       u->id, service_state_to_string(s->state));

                        switch (s->state) {

                        case SERVICE_START_PRE:
                                if (f == SERVICE_SUCCESS)
                                        service_enter_start(s);
                                else
                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                break;

                        case SERVICE_START:
                                if (s->type != SERVICE_FORKING)
                                        /* Maybe spurious event due to a reload that changed the type? */
                                        break;

                                if (f != SERVICE_SUCCESS) {
                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        bool has_start_post;
                                        int r;

                                        /* Let's try to load the pid file here if we can.
                                         * The PID file might actually be created by a START_POST
                                         * script. In that case don't worry if the loading fails. */

                                        has_start_post = !!s->exec_command[SERVICE_EXEC_START_POST];
                                        r = service_load_pid_file(s, !has_start_post);
                                        if (!has_start_post && r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || !cgroup_good(s))
                                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
                                                break;
                                        }
                                } else
                                        service_search_main_pid(s);

                                service_enter_start_post(s);
                                break;

                        case SERVICE_START_POST:
                                if (f != SERVICE_SUCCESS) {
                                        service_enter_stop(s, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        int r;

                                        r = service_load_pid_file(s, true);
                                        if (r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || !cgroup_good(s))
                                                        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                                                break;
                                        }
                                } else
                                        service_search_main_pid(s);

                                service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_RELOAD:
                                if (f == SERVICE_SUCCESS) {
                                        service_load_pid_file(s, true);
                                        service_search_main_pid(s);
                                }

                                s->reload_result = f;
                                service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_STOP:
                                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                break;

                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_stop_post(s, f);

                                /* If there is still a service
                                 * process around, wait until
                                 * that one quit, too */
                                break;

                        case SERVICE_STOP_POST:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:
                                service_enter_dead(s, f, true);
                                break;

                        default:
                                assert_not_reached("Uh, control process died at wrong time.");
                        }
                }
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);

        /* We got one SIGCHLD for the service, let's watch all
         * processes that are now running of the service, and watch
         * that. Among the PIDs we then watch will be children
         * reassigned to us, which hopefully allows us to identify
         * when all children are gone */
        unit_tidy_watch_pids(u, s->main_pid, s->control_pid);
        unit_watch_all_pids(u);

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(u->pids))
                service_notify_cgroup_empty_event(u);
}

static void service_timer_event(Unit *u, uint64_t elapsed, ev_timer* w) {
        Service *s = SERVICE(u);

        assert(s);
        assert(elapsed == 1);

        if (w == &s->watchdog_watch) {
                service_handle_watchdog(s);
                return;
        }

        assert(w == &s->timer_watch);

        switch (s->state) {

        case SERVICE_START_PRE:
        case SERVICE_START:
                log_warning_unit(u->id,
                                 "%s operation timed out. Terminating.", u->id);
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_START_POST:
                log_warning_unit(u->id,
                                 "%s operation timed out. Stopping.", u->id);
                service_enter_stop(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_RELOAD:
                log_warning_unit(u->id,
                                 "%s operation timed out. Stopping.", u->id);
                s->reload_result = SERVICE_FAILURE_TIMEOUT;
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP:
                log_warning_unit(u->id,
                                 "%s stopping timed out. Terminating.", u->id);
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(u->id,
                                         "%s stopping timed out. Killing.", u->id);
                        service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(u->id,
                                         "%s stopping timed out. Skipping SIGKILL.", u->id);
                        service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                }

                break;

        case SERVICE_STOP_SIGKILL:
                /* Uh, we sent a SIGKILL and it is still not gone?
                 * Must be something we cannot kill, so let's just be
                 * weirded out and continue */

                log_warning_unit(u->id,
                                 "%s still around after SIGKILL. Ignoring.", u->id);
                service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_POST:
                log_warning_unit(u->id,
                                 "%s stopping timed out (2). Terminating.", u->id);
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_FINAL_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(u->id,
                                         "%s stopping timed out (2). Killing.", u->id);
                        service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(u->id,
                                         "%s stopping timed out (2). Skipping SIGKILL. Entering failed mode.",
                                         u->id);
                        service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
                }

                break;

        case SERVICE_FINAL_SIGKILL:
                log_warning_unit(u->id,
                                 "%s still around after SIGKILL (2). Entering failed mode.", u->id);
                service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, true);
                break;

        case SERVICE_AUTO_RESTART:
                log_info_unit(u->id,
                              "%s holdoff time over, scheduling restart.", u->id);
                service_enter_restart(s);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

static void service_notify_message(Unit *u, pid_t pid, char **tags) {
        Service *s = SERVICE(u);
        const char *e;

        assert(u);

        if (s->notify_access == NOTIFY_NONE) {
                log_warning_unit(u->id,
                                 "%s: Got notification message from PID %lu, but reception is disabled.",
                                 u->id, (unsigned long) pid);
                return;
        }

        if (s->notify_access == NOTIFY_MAIN && s->main_pid != 0 && pid != s->main_pid) {
                log_warning_unit(u->id,
                                 "%s: Got notification message from PID %lu, but reception only permitted for PID %lu",
                                 u->id, (unsigned long) pid, (unsigned long) s->main_pid);
                return;
        }

        log_debug_unit(u->id,
                       "%s: Got message", u->id);

        /* Interpret MAINPID= */
        if ((e = strv_find_prefix(tags, "MAINPID=")) &&
            (s->state == SERVICE_START ||
             s->state == SERVICE_START_POST ||
             s->state == SERVICE_RUNNING ||
             s->state == SERVICE_RELOAD)) {

                if (parse_pid(e + 8, &pid) < 0)
                        log_warning_unit(u->id,
                                         "Failed to parse notification message %s", e);
                else {
                        log_debug_unit(u->id,
                                       "%s: got %s", u->id, e);
                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid);
                }
        }

        /* Interpret READY= */
        if (s->type == SERVICE_NOTIFY &&
            s->state == SERVICE_START &&
            strv_find(tags, "READY=1")) {
                log_debug_unit(u->id,
                               "%s: got READY=1", u->id);

                service_enter_start_post(s);
        }

        /* Interpret STATUS= */
        e = strv_find_prefix(tags, "STATUS=");
        if (e) {
                char *t;

                if (e[7]) {

                        if (!utf8_is_valid(e+7)) {
                                log_warning_unit(u->id,
                                                 "Status message in notification is not UTF-8 clean.");
                                return;
                        }

                        t = strdup(e+7);
                        if (!t) {
                                log_error_unit(u->id,
                                               "Failed to allocate string.");
                                return;
                        }

                        log_debug_unit(u->id,
                                       "%s: got %s", u->id, e);

                        free(s->status_text);
                        s->status_text = t;
                } else {
                        free(s->status_text);
                        s->status_text = NULL;
                }

        }
        if (strv_find(tags, "WATCHDOG=1")) {
                log_debug_unit(u->id,
                               "%s: got WATCHDOG=1", u->id);
                if (dual_timestamp_is_set(&s->watchdog_timestamp))
                        service_reset_watchdog(s);
        }

        /* Notify clients about changed status or main pid */
        unit_add_to_dbus_queue(u);
}

static int service_get_timeout(Unit *u, usec_t *timeout)
{
        Service *s = SERVICE(u);
        int r;

        if (!ev_is_active(&s->timer_watch))
                return 0;

        *timeout = (ev_now(u->manager->evloop) + ev_timer_remaining(u->manager->evloop, &s->timer_watch)) *
                USEC_PER_SEC;

        return 1;
}

#ifdef HAVE_SYSV_COMPAT

static int service_enumerate(Manager *m) {
        char **p;
        unsigned i;
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *path = NULL, *fpath = NULL, *name = NULL;
        Set *runlevel_services[ELEMENTSOF(rcnd_table)] = {};
        _cleanup_set_free_ Set *shutdown_services = NULL;
        Unit *service;
        Iterator j;
        int r;

        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return 0;

        STRV_FOREACH(p, m->lookup_paths.sysvrcnd_path)
                for (i = 0; i < ELEMENTSOF(rcnd_table); i ++) {
                        struct dirent *de;

                        free(path);
                        path = strjoin(*p, "/", rcnd_table[i].path, NULL);
                        if (!path) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (d)
                                closedir(d);

                        d = opendir(path);
                        if (!d) {
                                if (errno != ENOENT)
                                        log_warning("opendir(%s) failed: %s", path, strerror(errno));

                                continue;
                        }

                        while ((de = readdir(d))) {
                                int a, b;

                                if (ignore_file(de->d_name))
                                        continue;

                                if (de->d_name[0] != 'S' && de->d_name[0] != 'K')
                                        continue;

                                if (strlen(de->d_name) < 4)
                                        continue;

                                a = undecchar(de->d_name[1]);
                                b = undecchar(de->d_name[2]);

                                if (a < 0 || b < 0)
                                        continue;

                                free(fpath);
                                fpath = strjoin(path, "/", de->d_name, NULL);
                                if (!fpath) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if (access(fpath, X_OK) < 0) {

                                        if (errno != ENOENT)
                                                log_warning("access() failed on %s: %s", fpath, strerror(errno));

                                        continue;
                                }

                                free(name);
                                name = sysv_translate_name(de->d_name + 3);
                                if (!name) {
                                        r = log_oom();
                                        goto finish;
                                }

                                r = manager_load_unit_prepare(m, name, NULL, NULL, &service);
                                if (r < 0) {
                                        log_warning("Failed to prepare unit %s: %s", name, strerror(-r));
                                        continue;
                                }

                                if (de->d_name[0] == 'S')  {

                                        if (rcnd_table[i].type == RUNLEVEL_UP) {
                                                SERVICE(service)->sysv_start_priority_from_rcnd =
                                                        MAX(a*10 + b, SERVICE(service)->sysv_start_priority_from_rcnd);

                                                SERVICE(service)->sysv_enabled = true;
                                        }

                                        r = set_ensure_allocated(&runlevel_services[i],
                                                                 trivial_hash_func, trivial_compare_func);
                                        if (r < 0)
                                                goto finish;

                                        r = set_put(runlevel_services[i], service);
                                        if (r < 0)
                                                goto finish;

                                } else if (de->d_name[0] == 'K' &&
                                           (rcnd_table[i].type == RUNLEVEL_DOWN)) {

                                        r = set_ensure_allocated(&shutdown_services,
                                                                 trivial_hash_func, trivial_compare_func);
                                        if (r < 0)
                                                goto finish;

                                        r = set_put(shutdown_services, service);
                                        if (r < 0)
                                                goto finish;
                                }
                        }
                }

        /* Now we loaded all stubs and are aware of the lowest
        start-up priority for all services, not let's actually load
        the services, this will also tell us which services are
        actually native now */
        manager_dispatch_load_queue(m);

        /* If this is a native service, rely on native ways to pull in
         * a service, don't pull it in via sysv rcN.d links. */
        for (i = 0; i < ELEMENTSOF(rcnd_table); i ++)
                SET_FOREACH(service, runlevel_services[i], j) {
                        service = unit_follow_merge(service);

                        if (service->fragment_path)
                                continue;

                        r = unit_add_two_dependencies_by_name_inverse(
                                service, UNIT_AFTER, UNIT_WANTS,
                                rcnd_table[i].target, NULL, true);
                        if (r < 0)
                                goto finish;
                }

        /* We honour K links only for halt/reboot. For the normal
         * runlevels we assume the stop jobs will be implicitly added
         * by the core logic. Also, we don't really distinguish here
         * between the runlevels 0 and 6 and just add them to the
         * special shutdown target. */
        SET_FOREACH(service, shutdown_services, j) {
                service = unit_follow_merge(service);

                if (service->fragment_path)
                        continue;

                r = unit_add_two_dependencies_by_name(
                        service, UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, NULL, true);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:

        for (i = 0; i < ELEMENTSOF(rcnd_table); i++)
                set_free(runlevel_services[i]);

        return r;
}
#endif

static void service_bus_name_owner_change(
                Unit *u,
                const char *name,
                const char *old_owner,
                const char *new_owner) {

        Service *s = SERVICE(u);

        assert(s);
        assert(name);

        assert(streq(s->bus_name, name));
        assert(old_owner || new_owner);

        if (old_owner && new_owner)
                log_debug_unit(u->id,
                               "%s's D-Bus name %s changed owner from %s to %s",
                               u->id, name, old_owner, new_owner);
        else if (old_owner)
                log_debug_unit(u->id,
                               "%s's D-Bus name %s no longer registered by %s",
                               u->id, name, old_owner);
        else
                log_debug_unit(u->id,
                               "%s's D-Bus name %s now registered by %s",
                               u->id, name, new_owner);

        s->bus_name_good = !!new_owner;

        if (s->type == SERVICE_DBUS) {

                /* service_enter_running() will figure out what to
                 * do */
                if (s->state == SERVICE_RUNNING)
                        service_enter_running(s, SERVICE_SUCCESS);
                else if (s->state == SERVICE_START && new_owner)
                        service_enter_start_post(s);

        } else if (new_owner &&
                   s->main_pid <= 0 &&
                   (s->state == SERVICE_START ||
                    s->state == SERVICE_START_POST ||
                    s->state == SERVICE_RUNNING ||
                    s->state == SERVICE_RELOAD)) {

                /* Try to acquire PID from bus service */
                log_debug_unit(u->id,
                               "Trying to acquire PID from D-Bus name...");

                bus_query_pid(u->manager, name);
        }
}

static void service_bus_query_pid_done(
                Unit *u,
                const char *name,
                pid_t pid) {

        Service *s = SERVICE(u);

        assert(s);
        assert(name);

        log_debug_unit(u->id,
                       "%s's D-Bus name %s is now owned by process %u",
                       u->id, name, (unsigned) pid);

        if (s->main_pid <= 0 &&
            (s->state == SERVICE_START ||
             s->state == SERVICE_START_POST ||
             s->state == SERVICE_RUNNING ||
             s->state == SERVICE_RELOAD)){
                service_set_main_pid(s, pid);
                unit_watch_pid(UNIT(s), pid);
        }
}

int service_set_socket_fd(Service *s, int fd, Socket *sock) {

        assert(s);
        assert(fd >= 0);

        /* This is called by the socket code when instantiating a new
         * service for a stream socket and the socket needs to be
         * configured. */

        if (UNIT(s)->load_state != UNIT_LOADED)
                return -EINVAL;

        if (s->socket_fd >= 0)
                return -EBUSY;

        if (s->state != SERVICE_DEAD)
                return -EAGAIN;

        s->socket_fd = fd;
        s->got_socket_fd = true;

        unit_ref_set(&s->accept_socket, UNIT(sock));

        return unit_add_two_dependencies(UNIT(sock), UNIT_BEFORE, UNIT_TRIGGERS, UNIT(s), false);
}

static void service_reset_failed(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_FAILED)
                service_set_state(s, SERVICE_DEAD);

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;

        RATELIMIT_RESET(s->start_limit);
}

static int service_kill(Unit *u, KillWho who, int signo, DBusError *error) {
        Service *s = SERVICE(u);

        return unit_kill_common(u, who, signo, s->main_pid, s->control_pid, error);
}

static const char* const service_state_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_START] = "start",
        [SERVICE_START_POST] = "start-post",
        [SERVICE_RUNNING] = "running",
        [SERVICE_EXITED] = "exited",
        [SERVICE_RELOAD] = "reload",
        [SERVICE_STOP] = "stop",
        [SERVICE_STOP_SIGTERM] = "stop-sigterm",
        [SERVICE_STOP_SIGKILL] = "stop-sigkill",
        [SERVICE_STOP_POST] = "stop-post",
        [SERVICE_FINAL_SIGTERM] = "final-sigterm",
        [SERVICE_FINAL_SIGKILL] = "final-sigkill",
        [SERVICE_FAILED] = "failed",
        [SERVICE_AUTO_RESTART] = "auto-restart",
};

DEFINE_STRING_TABLE_LOOKUP(service_state, ServiceState);

static const char* const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_RESTART_NO] = "no",
        [SERVICE_RESTART_ON_SUCCESS] = "on-success",
        [SERVICE_RESTART_ON_FAILURE] = "on-failure",
        [SERVICE_RESTART_ON_WATCHDOG] = "on-watchdog",
        [SERVICE_RESTART_ON_ABORT] = "on-abort",
        [SERVICE_RESTART_ALWAYS] = "always"
};

DEFINE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

static const char* const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_SIMPLE] = "simple",
        [SERVICE_FORKING] = "forking",
        [SERVICE_ONESHOT] = "oneshot",
        [SERVICE_DBUS] = "dbus",
        [SERVICE_NOTIFY] = "notify",
        [SERVICE_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char* const service_exec_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_START_PRE] = "ExecStartPre",
        [SERVICE_EXEC_START] = "ExecStart",
        [SERVICE_EXEC_START_POST] = "ExecStartPost",
        [SERVICE_EXEC_RELOAD] = "ExecReload",
        [SERVICE_EXEC_STOP] = "ExecStop",
        [SERVICE_EXEC_STOP_POST] = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

static const char* const notify_access_table[_NOTIFY_ACCESS_MAX] = {
        [NOTIFY_NONE] = "none",
        [NOTIFY_MAIN] = "main",
        [NOTIFY_ALL] = "all"
};

DEFINE_STRING_TABLE_LOOKUP(notify_access, NotifyAccess);

static const char* const service_result_table[_SERVICE_RESULT_MAX] = {
        [SERVICE_SUCCESS] = "success",
        [SERVICE_FAILURE_RESOURCES] = "resources",
        [SERVICE_FAILURE_TIMEOUT] = "timeout",
        [SERVICE_FAILURE_EXIT_CODE] = "exit-code",
        [SERVICE_FAILURE_SIGNAL] = "signal",
        [SERVICE_FAILURE_CORE_DUMP] = "core-dump",
        [SERVICE_FAILURE_WATCHDOG] = "watchdog",
        [SERVICE_FAILURE_START_LIMIT] = "start-limit"
};

DEFINE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

static const char* const start_limit_action_table[_SERVICE_START_LIMIT_MAX] = {
        [SERVICE_START_LIMIT_NONE] = "none",
        [SERVICE_START_LIMIT_REBOOT] = "reboot",
        [SERVICE_START_LIMIT_REBOOT_FORCE] = "reboot-force",
        [SERVICE_START_LIMIT_REBOOT_IMMEDIATE] = "reboot-immediate"
};
DEFINE_STRING_TABLE_LOOKUP(start_limit_action, StartLimitAction);

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),

        .sections =
                "Unit\0"
                "Service\0"
                "Install\0",

        .private_section = "Service",
        .exec_context_offset = offsetof(Service, exec_context),
#ifdef Use_CGroups
        .cgroup_context_offset = offsetof(Service, cgroup_context),
#endif

        .init = service_init,
        .done = service_done,
        .load = service_load,

        .coldplug = service_coldplug,

        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .can_reload = service_can_reload,

        .kill = service_kill,

        .serialize = service_serialize,
        .deserialize_item = service_deserialize_item,

        .active_state = service_active_state,
        .sub_state_to_string = service_sub_state_to_string,

        .check_gc = service_check_gc,
        .check_snapshot = service_check_snapshot,

        .sigchld_event = service_sigchld_event,
        .timer_event = service_timer_event,
        .fd_event = service_fd_event,

        .reset_failed = service_reset_failed,

        .notify_cgroup_empty = service_notify_cgroup_empty_event,
        .notify_message = service_notify_message,

        .bus_name_owner_change = service_bus_name_owner_change,
        .bus_query_pid_done = service_bus_query_pid_done,

        .bus_interface = SCHEDULER_DBUS_INTERFACE ".Service",
        .bus_message_handler = bus_service_message_handler,
        .bus_invalidating_properties =  bus_service_invalidating_properties,
        .bus_set_property = bus_service_set_property,
        .bus_commit_properties = bus_service_commit_properties,

        .can_transient = true,

#ifdef HAVE_SYSV_COMPAT
        .enumerate = service_enumerate,
#endif
        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Starting %s...",
                        [1] = "Stopping %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Started %s.",
                        [JOB_FAILED]     = "Failed to start %s.",
                        [JOB_DEPENDENCY] = "Dependency failed for %s.",
                        [JOB_TIMEOUT]    = "Timed out starting %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped %s.",
                        [JOB_FAILED]     = "Stopped (with error) %s.",
                        [JOB_TIMEOUT]    = "Timed out stopping %s.",
                },
        },
};
