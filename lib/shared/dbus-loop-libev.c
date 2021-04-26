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

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "dbus-loop-libev.h"
#include "ev-util.h"
#include "util.h"

static void bus_io_cb(struct ev_loop *evloop, ev_io *ev, int revents)
{
        DBusWatchFlags flags = 0;
        DBusWatch *watch = (DBusWatch *) ev->data;

        if (revents & EV_READ)
                flags |= DBUS_WATCH_READABLE;
        if (revents & EV_WRITE)
                flags |= DBUS_WATCH_WRITABLE;

        if (!dbus_watch_get_enabled(watch))
                return;
        dbus_watch_handle(watch, flags);
}

dbus_bool_t bus_add_watch(DBusWatch *watch, void *data)
{
        struct ev_loop *evloop = data;
        ev_io *ev;
        unsigned watchflags;
        int events = 0;

        assert(watch);
        assert(evloop);

        if (!(ev = new0(ev_io, 1)))
                return FALSE;

        watchflags = dbus_watch_get_flags(watch);
        if (watchflags & DBUS_WATCH_READABLE)
                events |= EV_READ;
        if (watchflags & DBUS_WATCH_WRITABLE)
                events |= EV_WRITE;

        ev_io_init(ev, bus_io_cb, dbus_watch_get_unix_fd(watch), events);
        ev->data = watch;

        if (dbus_watch_get_enabled(watch))
                ev_io_start(evloop, ev);

        dbus_watch_set_data(watch, ev, NULL);

        return TRUE;
}

void bus_remove_watch(DBusWatch *watch, void *data)
{
        struct ev_loop *evloop = data;
        ev_io *ev;

        ev = dbus_watch_get_data(watch);
        assert(ev);
        assert(evloop);

        ev_io_stop(evloop, ev);
        free(ev);

        /* safe_close(w->fd); */
}

void bus_toggle_watch(DBusWatch *watch, void *data)
{
        struct ev_loop *evloop = data;
        ev_io *ev;

        ev = dbus_watch_get_data(watch);
        assert(ev);
        assert(evloop);

        if (dbus_watch_get_enabled(watch))
                ev_io_start(evloop, ev);
        else
                ev_io_stop(evloop, ev);
}

static void bus_timer_cb(struct ev_loop *evloop, ev_timer *timer, int revents)
{
        DBusTimeout *timeout = timer->data;

        if (!(dbus_timeout_get_enabled(timeout)))
                return;

        dbus_timeout_handle(timeout);
}

dbus_bool_t bus_add_timeout(DBusTimeout *timeout, void *data)
{
        struct ev_loop *evloop = data;
        ev_timer *timer;
        double interval;

        assert(evloop);

        if (!(timer = new0(ev_timer, 1)))
                return FALSE;

        interval = dbus_timeout_get_interval(timeout) / 1000.0;

        ev_timer_init(timer, bus_timer_cb, interval, interval);
        timer->data = timeout;

        if (dbus_timeout_get_enabled(timeout))
                ev_timer_start(evloop, timer);

        dbus_timeout_set_data(timeout, timer, NULL);

        return TRUE;
}

void bus_remove_timeout(DBusTimeout *timeout, void *data)
{
        struct ev_loop *evloop = data;
        ev_timer *timer;

        timer = dbus_timeout_get_data(timeout);
        assert(timer);
        assert(evloop);

        ev_timer_stop(evloop, timer);
        free(timer);
}

void bus_toggle_timeout(DBusTimeout *timeout, void *data)
{
        struct ev_loop *evloop = data;
        ev_timer *timer;

        timer = dbus_timeout_get_data(timeout);
        assert(timer);
        assert(evloop);

        ev_timer_stop(evloop, timer);

        if (dbus_timeout_get_enabled(timeout)) {
                double interval = dbus_timeout_get_interval(timeout) / 1000.0;
                ev_timer_set(timer, interval, interval);
                ev_timer_start(evloop, timer);
        }
}

int bus_loop_open(struct ev_loop *evloop, DBusConnection *c)
{
        assert(c);
        if (!dbus_connection_set_watch_functions(
                    c, bus_add_watch, bus_remove_watch, bus_toggle_watch, evloop, NULL) ||
            !dbus_connection_set_timeout_functions(
                    c, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, evloop, NULL))
                return -ENOMEM;

        return 0;
}