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

  Copyright 2013 Lennart Poettering

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
#include <unistd.h>

#include "dbus-scope.h"
#include "def.h"
#include "ev-util.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "scope.h"
#include "special.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD] = UNIT_INACTIVE,
        [SCOPE_RUNNING] = UNIT_ACTIVE,
        [SCOPE_ABANDONED] = UNIT_ACTIVE,
        [SCOPE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SCOPE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SCOPE_FAILED] = UNIT_FAILED
};

static void scope_init(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_stop_usec = u->manager->default_timeout_stop_usec;

        ev_timer_zero(s->timer_watch);

#ifdef Use_CGroups
        cgroup_context_init(&s->cgroup_context);
#endif
        kill_context_init(&s->kill_context);

        UNIT(s)->ignore_on_isolate = true;
        UNIT(s)->ignore_on_snapshot = true;
}

static void scope_done(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);

#ifdef Use_CGroups
        cgroup_context_done(&s->cgroup_context);

        free(s->controller);
        s->controller = NULL;
#endif

        unit_unwatch_timer(u, &s->timer_watch);
}

static void scope_set_state(Scope *s, ScopeState state) {
        ScopeState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SCOPE_STOP_SIGTERM &&
            state != SCOPE_STOP_SIGKILL)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state == SCOPE_DEAD || state == SCOPE_FAILED)
                unit_unwatch_all_pids(UNIT(s));

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(s)->id,
                          scope_state_to_string(old_state),
                          scope_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], true);
}

static int scope_add_default_dependencies(Scope *s) {
        int r;

        assert(s);

        /* Make sure scopes are unloaded on shutdown */
        r = unit_add_two_dependencies_by_name(
                        UNIT(s),
                        UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, NULL, true);
        if (r < 0)
                return r;

        return 0;
}

static int scope_verify(Scope *s) {
        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (set_size(UNIT(s)->pids) <= 0 && UNIT(s)->manager->n_reloading <= 0) {
                log_error_unit(UNIT(s)->id, "Scope %s has no PIDs. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        return 0;
}

static int scope_load(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(u->load_state == UNIT_STUB);

        if (!u->transient && UNIT(s)->manager->n_reloading <= 0)
                return -ENOENT;

        u->load_state = UNIT_LOADED;

        r = unit_load_dropin(u);
        if (r < 0)
                return r;

        r = unit_add_default_slice(u);
        if (r < 0)
                return r;

        if (u->default_dependencies) {
                r = scope_add_default_dependencies(s);
                if (r < 0)
                        return r;
        }

        return scope_verify(s);
}

static int scope_coldplug(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(s->state == SCOPE_DEAD);

        if (s->deserialized_state != s->state) {

                if ((s->deserialized_state == SCOPE_STOP_SIGKILL || s->deserialized_state == SCOPE_STOP_SIGTERM)
                    && s->timeout_stop_usec > 0) {
                        r = unit_watch_timer(UNIT(s), s->timeout_stop_usec, &s->timer_watch);
                        if (r < 0)

                                return r;
                }

                if (s->deserialized_state != SCOPE_DEAD && s->deserialized_state != SCOPE_FAILED)
                        unit_watch_all_pids(UNIT(s));

                scope_set_state(s, s->deserialized_state);
        }

        return 0;
}

static void scope_dump(Unit *u, FILE *f, const char *prefix) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(f);

        fprintf(f,
                "%sScope State: %s\n"
                "%sResult: %s\n",
                prefix, scope_state_to_string(s->state),
                prefix, scope_result_to_string(s->result));

#ifdef Use_CGroups
        cgroup_context_dump(&s->cgroup_context, f, prefix);
#endif
        kill_context_dump(&s->kill_context, f, prefix);
}

static void scope_enter_dead(Scope *s, ScopeResult f) {
        assert(s);

        if (f != SCOPE_SUCCESS)
                s->result = f;

        scope_set_state(s, s->result != SCOPE_SUCCESS ? SCOPE_FAILED : SCOPE_DEAD);
}

static void scope_enter_signal(Scope *s, ScopeState state, ScopeResult f) {
        bool skip_signal = false;
        int r;

        assert(s);

        if (f != SCOPE_SUCCESS)
                s->result = f;

        unit_watch_all_pids(UNIT(s));

        /* If we have a controller set let's ask the controller nicely
         * to terminate the scope, instead of us going directly into
         * SIGTERM beserk mode */
        if (state == SCOPE_STOP_SIGTERM)
                skip_signal = bus_scope_send_request_stop(s) > 0;

        if (!skip_signal) {
                r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        state != SCOPE_STOP_SIGTERM,
                        -1, -1, false);

                if (r < 0)
                        goto fail;
        } else
                r = 1;

        if (r > 0) {
                if (s->timeout_stop_usec > 0) {
                        r = unit_watch_timer(UNIT(s), s->timeout_stop_usec, &s->timer_watch);
                        if (r < 0)
                                goto fail;
                }

                scope_set_state(s, state);
        } else
                scope_enter_dead(s, SCOPE_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to kill processes: %s", UNIT(s)->id, strerror(-r));

        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
}

static int scope_start(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);

        if (s->state == SCOPE_FAILED)
                return -EPERM;

        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return -EAGAIN;

        assert(s->state == SCOPE_DEAD);

        if (!u->transient && UNIT(s)->manager->n_reloading <= 0)
                return -ENOENT;

#if defined(Use_CGroups)
        r = unit_realize_cgroup(u);
        if (r < 0) {
                log_error("Failed to realize cgroup: %s", strerror(-r));
                return r;
        }

        r = cg_attach_many_everywhere(u->manager->cgroup_supported, u->cgroup_path, UNIT(s)->pids);
        if (r < 0)
                return r;
#elif defined(Use_PTGroups)
        r = unit_realize_ptgroup(u);
        if (r < 0) {
                log_error("Failed to realize ptgroup: %s", strerror(-r));
                return r;
        }

        r = ptgroup_attach_many(u->ptgroup, u->manager->pt_manager, UNIT(s)->pids);
        if (r < 0)
                return r;
#endif

        s->result = SCOPE_SUCCESS;

        scope_set_state(s, SCOPE_RUNNING);
        return 0;
}

static int scope_stop(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);

        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return 0;

        assert(s->state == SCOPE_RUNNING ||
               s->state == SCOPE_ABANDONED);

        scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_SUCCESS);
        return 0;
}

static void scope_reset_failed(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);

        if (s->state == SCOPE_FAILED)
                scope_set_state(s, SCOPE_DEAD);

        s->result = SCOPE_SUCCESS;
}

static int scope_kill(Unit *u, KillWho who, int signo, DBusError *error) {
        return unit_kill_common(u, who, signo, -1, -1, error);
}

static int scope_get_timeout(Unit *u, usec_t *timeout)
{
        Scope *s = SCOPE(u);
        int r;

        if (!ev_is_active(&s->timer_watch))
                return 0;


        *timeout = (ev_now(u->manager->evloop) + ev_timer_remaining(u->manager->evloop, &s->timer_watch)) *
                USEC_PER_SEC;

        return 1;
}

static int scope_serialize(Unit *u, FILE *f, FDSet *fds) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", scope_state_to_string(s->state));
        return 0;
}

static int scope_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Scope *s = SCOPE(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                ScopeState state;

                state = scope_state_from_string(value);
                if (state < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static bool scope_check_gc(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);

        /* Never clean up scopes that still have a process around,
         * even if the scope is formally dead. */

#ifdef Use_CGroups
        if (u->cgroup_path) {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, UNIT(s)->cgroup_path, true);
                if (r <= 0)
                        return true;
        }
#else
        if (u->ptgroup) {
                return !ptg_is_empty_recursive(UNIT(s)->ptgroup);
        }
#endif

        return false;
}

static void scope_notify_cgroup_empty_event(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);

        log_debug_unit(u->id, "%s: cgroup is empty", u->id);

        if (s->state == SCOPE_RUNNING || s->state == SCOPE_ABANDONED ||
            s->state == SCOPE_STOP_SIGTERM || SCOPE_STOP_SIGKILL)
                scope_enter_dead(s, SCOPE_SUCCESS);
}

static void scope_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        /* If we get a SIGCHLD event for one of the processes we were
           interested in, then we look for others to watch, under the
           assumption that we'll sooner or later get a SIGCHLD for
           them, as the original process we watched was probably the
           parent of them, and they are hence now our children. */

        unit_tidy_watch_pids(u, 0, 0);
        unit_watch_all_pids(u);

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(u->pids))
                scope_notify_cgroup_empty_event(u);
}

static void scope_timer_event(Unit *u, uint64_t elapsed, ev_timer *w)
{
        Scope *s = SCOPE(u);

        assert(s);
        assert(elapsed == 1);
        assert(w == &s->timer_watch);

        switch (s->state) {

        case SCOPE_STOP_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(u->id, "%s stopping timed out. Killing.", u->id);
                        scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(u->id, "%s stopping timed out. Skipping SIGKILL.", u->id);
                        scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                }

                break;

        case SCOPE_STOP_SIGKILL:
                log_warning_unit(u->id, "%s still around after SIGKILL. Ignoring.", u->id);
                scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

int scope_abandon(Scope *s) {
        assert(s);

        if (s->state != SCOPE_RUNNING && s->state != SCOPE_ABANDONED)
                return -ESTALE;

        free(s->controller);
        s->controller = NULL;

        /* The client is no longer watching the remaining processes,
         * so let's step in here, under the assumption that the
         * remaining processes will be sooner or later reassigned to
         * us as parent. */

        unit_tidy_watch_pids(UNIT(s), 0, 0);
        unit_watch_all_pids(UNIT(s));

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(UNIT(s)->pids))
                scope_notify_cgroup_empty_event(UNIT(s));
        else
                scope_set_state(s, SCOPE_ABANDONED);

        return 0;
}

_pure_ static UnitActiveState scope_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SCOPE(u)->state];
}

_pure_ static const char *scope_sub_state_to_string(Unit *u) {
        assert(u);

        return scope_state_to_string(SCOPE(u)->state);
}

static const char* const scope_state_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD] = "dead",
        [SCOPE_RUNNING] = "running",
        [SCOPE_ABANDONED] = "abandoned",
        [SCOPE_STOP_SIGTERM] = "stop-sigterm",
        [SCOPE_STOP_SIGKILL] = "stop-sigkill",
        [SCOPE_FAILED] = "failed",
};

DEFINE_STRING_TABLE_LOOKUP(scope_state, ScopeState);

static const char* const scope_result_table[_SCOPE_RESULT_MAX] = {
        [SCOPE_SUCCESS] = "success",
        [SCOPE_FAILURE_RESOURCES] = "resources",
        [SCOPE_FAILURE_TIMEOUT] = "timeout",
};

DEFINE_STRING_TABLE_LOOKUP(scope_result, ScopeResult);

const UnitVTable scope_vtable = {
        .object_size = sizeof(Scope),
        .sections =
                "Unit\0"
                "Scope\0"
                "Install\0",

        .private_section = "Scope",
#ifdef Use_CGroups
        .cgroup_context_offset = offsetof(Socket, cgroup_context),
#endif

        .no_alias = true,
        .no_instances = true,

        .init = scope_init,
        .load = scope_load,
        .done = scope_done,

        .coldplug = scope_coldplug,

        .dump = scope_dump,

        .start = scope_start,
        .stop = scope_stop,

        .kill = scope_kill,

        .get_timeout = scope_get_timeout,

        .serialize = scope_serialize,
        .deserialize_item = scope_deserialize_item,

        .active_state = scope_active_state,
        .sub_state_to_string = scope_sub_state_to_string,

        .check_gc = scope_check_gc,

        .sigchld_event = scope_sigchld_event,

        .timer_event = scope_timer_event,

        .reset_failed = scope_reset_failed,

        .notify_cgroup_empty = scope_notify_cgroup_empty_event,

        .bus_interface = SCHEDULER_DBUS_INTERFACE ".Scope",
        .bus_message_handler = bus_scope_message_handler,
        .bus_set_property = bus_scope_set_property,
        .bus_commit_properties = bus_scope_commit_properties,

        .can_transient = true
};
