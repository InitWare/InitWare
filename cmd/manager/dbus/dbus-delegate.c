/*
 *	LICENCE NOTICE
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 *
 *	Copyright Notice
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */

#include "dbus/dbus-delegate.h"
#include "dbus-common.h"
#include "dbus/dbus-unit.h"
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
