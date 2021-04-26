/*******************************************************************

        LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

        Copyright Notice

    (c) 2021 David Mackay
        All rights reserved.

*********************************************************************/
/**
 * D-Bus integration for libev.
 */

#ifndef DBUS_LOOP_LIBEV_H
#        define DBUS_LOOP_LIBEV_H_

#        include <dbus/dbus.h>

#        include "ev-util.h"

dbus_bool_t bus_add_watch(DBusWatch *watch, void *data);
void bus_remove_watch(DBusWatch *watch, void *data);
void bus_toggle_watch(DBusWatch *watch, void *data);
dbus_bool_t bus_add_timeout(DBusTimeout *timeout, void *data);
void bus_remove_timeout(DBusTimeout *timeout, void *data);
void bus_toggle_timeout(DBusTimeout *timeout, void *data);

int bus_loop_open(struct ev_loop *loop, DBusConnection *c);
int bus_loop_dispatch(int fd);

#endif