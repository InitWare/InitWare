/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "dbus-delegate.h"
#include "dbus-common.h"
#include "dbus-unit.h"
#include "selinux-access.h"

#define BUS_DELEGATE_INTERFACE                                          \
	" <interface name=\"" SCHEDULER_DBUS_INTERFACE                  \
	".Delegate\">\n"                                                \
	"  <property name=\"SysFSPath\" type=\"s\" access=\"read\"/>\n" \
	" </interface>\n"

#define INTROSPECTION                                                                 \
	DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                                     \
	"<node>\n" BUS_UNIT_INTERFACE BUS_DELEGATE_INTERFACE BUS_PROPERTIES_INTERFACE \
	    BUS_PEER_INTERFACE BUS_INTROSPECTABLE_INTERFACE "</node>\n"

#define INTERFACES_LIST          \
	BUS_UNIT_INTERFACES_LIST \
	SCHEDULER_DBUS_INTERFACE ".Delegate\0"

const char bus_delegate_interface[] _introspect_("Delegate") = BUS_DELEGATE_INTERFACE;

const char bus_delegate_invalidating_properties[] = "Restarter\0";

static int bus_delegate_append_restarter(DBusMessageIter *i, const char *property, void *data)
{
	Unit *u = data, *restarter;
	const char *t;

	assert(i);
	assert(property);
	assert(u);

	restarter = DELEGATE(u)->restarter;
	t = restarter ? restarter->id : "";

	return dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t) ? 0 : -ENOMEM;
}

/* clang-format off */
static const BusProperty bus_delegate_properties[] = {
        { "Restarter", bus_delegate_append_restarter, "s", 0},
        { NULL, }
};
/* clang-format on */

DBusHandlerResult bus_delegate_message_handler(Unit *u, DBusConnection *c, DBusMessage *message)
{
	Delegate *d = DELEGATE(u);
	/* clang-format off */
	const BusBoundProperties bps[] = {
                { SCHEDULER_DBUS_INTERFACE ".Unit",   bus_unit_properties,   u },
                { SCHEDULER_DBUS_INTERFACE ".Delegate", bus_delegate_properties, d },
                { NULL, }
        };
	/* clang-format on */

	SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

	return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}
