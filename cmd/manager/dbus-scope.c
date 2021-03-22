/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "dbus-unit.h"
#include "dbus-common.h"
#include "dbus-cgroup.h"
#include "dbus-kill.h"
#include "selinux-access.h"
#include "dbus-scope.h"

#define BUS_SCOPE_INTERFACE                                             \
        " <interface name=\"org.freedesktop.systemd1.Scope\">\n"        \
        "  <method name=\"Abandon\"/>\n"                                \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        "  <property name=\"Controller\" type=\"s\" access=\"read\"/>\n"\
        "  <property name=\"TimeoutStopUSec\" type=\"t\" access=\"read\"/>\n" \
        BUS_KILL_CONTEXT_INTERFACE                                      \
        BUS_CGROUP_CONTEXT_INTERFACE                                    \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        "  <signal name=\"RequestStop\"/>\n"                            \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SCOPE_INTERFACE                                             \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Scope\0"

const char bus_scope_interface[] _introspect_("Scope") = BUS_SCOPE_INTERFACE;

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_scope_append_scope_result, scope_result, ScopeResult);

static const BusProperty bus_scope_properties[] = {
        { "Controller",             bus_property_append_string,    "s", offsetof(Scope, controller)        },
        { "TimeoutStopUSec",        bus_property_append_usec,      "t", offsetof(Scope, timeout_stop_usec) },
        { "Result",                 bus_scope_append_scope_result, "s", offsetof(Scope, result)            },
        {}
};

DBusHandlerResult bus_scope_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Scope *s = SCOPE(u);
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Scope", "Abandon")) {
                int r;

                r = scope_abandon(s);
                if (r < 0)
                        log_debug("Failed to mark scope %s as abandoned : Scope is not running", UNIT(s)->id);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;
        } else {
                const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",  bus_unit_properties,           u },
                { "org.freedesktop.systemd1.Scope", bus_unit_cgroup_properties,    u },
                { "org.freedesktop.systemd1.Scope", bus_scope_properties,          s },
                { "org.freedesktop.systemd1.Scope", bus_cgroup_context_properties, &s->cgroup_context },
                { "org.freedesktop.systemd1.Scope", bus_kill_context_properties,   &s->kill_context   },
                {}
                };

               return  bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
        }

        if (reply)
                if (!bus_maybe_send_reply(c, message, reply))
                        goto oom;

        return DBUS_HANDLER_RESULT_HANDLED;
oom:
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static int bus_scope_set_transient_property(
                Scope *s,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        int r;

        assert(name);
        assert(s);
        assert(i);

        if (streq(name, "PIDs")) {
                DBusMessageIter sub;
                unsigned n = 0;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(i) != DBUS_TYPE_UINT32)
                        return -EINVAL;

                dbus_message_iter_recurse(i, &sub);
                while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32) {
                        uint32_t pid;

                        dbus_message_iter_get_basic(&sub, &pid);

                        if (pid <= 1)
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                r = unit_watch_pid(UNIT(s), pid);
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }

                        dbus_message_iter_next(&sub);
                        n++;
                }

                if (n <= 0)
                        return -EINVAL;

                return 1;

        } else if (streq(name, "Controller")) {
                const char *controller;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &controller);

                if (!isempty(controller) && !bus_service_name_is_valid(controller))
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        char *c = NULL;

                        if (!isempty(controller)) {
                                c = strdup(controller);
                                if (!c)
                                        return -ENOMEM;
                        }

                        free(s->controller);
                        s->controller = c;
                }

                return 1;
        } else if (streq(name, "TimeoutStopUSec")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_UINT64)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        uint64_t t;

                        dbus_message_iter_get_basic(i, &t);

                        s->timeout_stop_usec = t;

                        unit_write_drop_in_format(UNIT(s), mode, name, "[Scope]\nTimeoutStopSec=%lluus\n", (unsigned long long) t);
                }

                return 1;
        }

        return 0;
}

int bus_scope_set_property(
                Unit *u,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        Scope *s = SCOPE(u);
        int r;

        assert(name);
        assert(u);
        assert(i);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, i, mode, error);
        if (r != 0)
                return r;

        if (u->load_state == UNIT_STUB) {
                /* While we are created we still accept PIDs */

                r = bus_scope_set_transient_property(s, name, i, mode, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, i, mode, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_scope_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);
        return 0;
}

int bus_scope_send_request_stop(Scope *s) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(s);

        if (!s->controller)
                return 0;

        p = unit_dbus_path(UNIT(s));
        if (!p)
                return -ENOMEM;

        m = dbus_message_new_signal(p,
                                    "org.freedesktop.systemd1.Scope",
                                    "RequestStop");
        if (!m)
                return 0;

        r = dbus_message_set_destination(m, s->controller);
        if (!r)
                return 0;

        return dbus_connection_send(UNIT(s)->manager->api_bus, m, NULL);
}
