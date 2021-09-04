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

#include "dbus/dbus-cgroup.h"
#include "dbus-common.h"
#include "dbus/dbus-unit.h"
#include "selinux-access.h"


#define BUS_SLICE_INTERFACE                                             \
        " <interface name=\"" SCHEDULER_DBUS_INTERFACE ".Slice\">\n"        \
        BUS_UNIT_CGROUP_INTERFACE                                       \
        BUS_CGROUP_CONTEXT_INTERFACE                                    \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SLICE_INTERFACE                                             \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        SCHEDULER_DBUS_INTERFACE ".Slice\0"

const char bus_slice_interface[] _introspect_("Slice") = BUS_SLICE_INTERFACE;

DBusHandlerResult bus_slice_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Slice *s = SLICE(u);

        const BusBoundProperties bps[] = {
                { SCHEDULER_DBUS_INTERFACE ".Unit",  bus_unit_properties,           u },
                { SCHEDULER_DBUS_INTERFACE ".Slice", bus_unit_cgroup_properties,    u },
#ifdef Use_CGroups
                { SCHEDULER_DBUS_INTERFACE ".Slice", bus_cgroup_context_properties, &s->cgroup_context },
#endif
                {}
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}

int bus_slice_set_property(
                Unit *u,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        Slice *s = SLICE(u);
        int r;

        assert(name);
        assert(u);
        assert(i);

#ifdef Use_CGroup
        r = bus_cgroup_set_property(u, &s->cgroup_context, name, i, mode, error);
#else
        unimplemented_msg("bus_cgroup_set_property");
        r = 0;
#endif
        if (r != 0)
                return r;

        return 0;
}

int bus_slice_commit_properties(Unit *u) {
        assert(u);

#ifdef Use_CGroups
        unit_realize_cgroup(u);
#endif
        return 0;
}
