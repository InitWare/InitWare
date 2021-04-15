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

  Copyright 2011 Lennart Poettering

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

#include <sys/event.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "dbus-common.h"
#include "dbus-loop.h"
#include "util.h"

/* Minimal implementation of the dbus loop which integrates all dbus
 * events into a single epoll fd which we can triviall integrate with
 * other loops. Note that this is not used in the main systemd daemon
 * since we run a more elaborate mainloop there. */

typedef struct EpollData {
        int fd;
        void *object;
        bool is_timeout : 1;
        bool fd_is_dupped : 1;
} EpollData;

static dbus_bool_t add_watch(DBusWatch *watch, void *data) {
        _cleanup_free_ EpollData *e = NULL;
        struct kevent kev = {};
        int kq = PTR_TO_INT(data);
        int flags;

        assert(watch);

        e = new0(EpollData, 1);
        if (!e)
                return FALSE;

        e->fd = dbus_watch_get_unix_fd(watch);
        e->object = watch;
        e->is_timeout = false;

        flags = dbus_watch_get_flags(watch);

        if (flags & DBUS_WATCH_READABLE) {
                EV_SET(&kev, e->fd, EVFILT_READ, EV_ADD, 0, 0, e);
                if (kevent(kq, &kev, 1, NULL, 0, NULL))
                        return FALSE;
        }
        if (flags & DBUS_WATCH_WRITABLE) {
                EV_SET(&kev, e->fd, EVFILT_READ, EV_ADD, 0, 0, e);
                if (kevent(kq, &kev, 1, NULL, 0, NULL))
                        return FALSE;
        }

        dbus_watch_set_data(watch, e, NULL);
        e = NULL; /* prevent freeing */

        return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data) {
        _cleanup_free_ EpollData *e = NULL;
        int kq = PTR_TO_INT(data);
        int flags;
        struct kevent kev;

        assert(watch);

        e = dbus_watch_get_data(watch);
        if (!e)
                return;

        flags = dbus_watch_get_flags(watch);

        if (flags & DBUS_WATCH_READABLE) {
                EV_SET(&kev, e->fd, EVFILT_READ, EV_DELETE, 0, 0, e);
                if (kevent(kq, &kev, 1, NULL, 0, NULL)) {
                        printf("Errno: %m\n");
                }
        }
        if (flags & DBUS_WATCH_WRITABLE) {
                EV_SET(&kev, e->fd, EVFILT_READ, EV_DELETE, 0, 0, e);
                if (kevent(kq, &kev, 1, NULL, 0, NULL)) {
                        printf("Errno: %m\n");
                }
        }

        safe_close(e->fd);
}

static void toggle_watch(DBusWatch *watch, void *data) {
        EpollData *e;
        struct kevent kev;
        int read_act = EV_DELETE;
        int write_act = EV_DELETE;
        int flags;
        int kq = PTR_TO_INT(data);

        assert(watch);

        e = dbus_watch_get_data(watch);
        if (!e)
                return;

        flags = dbus_watch_get_flags(watch);

        if (flags & DBUS_WATCH_READABLE)
                read_act = EV_ADD;
        if (flags & DBUS_WATCH_WRITABLE)
                write_act = EV_ADD;

        EV_SET(&kev, e->fd, EVFILT_READ, read_act, 0, 0, e);
        if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
                printf("Errno: %m\n");
        }

        EV_SET(&kev, e->fd, EVFILT_WRITE, write_act, 0, 0, e);
        if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
                printf("Errno: %m\n");
        }
}

static int timeout_arm(EpollData *e) {
#if 0
        struct itimerspec its = {};

        assert(e);
        assert(e->is_timeout);

        if (dbus_timeout_get_enabled(e->object)) {
                timespec_store(&its.it_value, dbus_timeout_get_interval(e->object) * USEC_PER_MSEC);
                its.it_interval = its.it_value;
        }

        if (timerfd_settime(e->fd, 0, &its, NULL) < 0)
                return -errno;
#endif
        return 0;
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data) {
#if 0
        EpollData *e;
        struct epoll_event ev = {};

        assert(timeout);

        e = new0(EpollData, 1);
        if (!e)
                return FALSE;

        e->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (e->fd < 0)
                goto fail;

        e->object = timeout;
        e->is_timeout = true;

        if (timeout_arm(e) < 0)
                goto fail;

        ev.events = EPOLLIN;
        ev.data.ptr = e;

        if (epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_ADD, e->fd, &ev) < 0)
                goto fail;

        dbus_timeout_set_data(timeout, e, NULL);

        return TRUE;

fail:
        safe_close(e->fd);

        free(e);
        return FALSE;
#else
        return TRUE;
#endif
}

static void remove_timeout(DBusTimeout *timeout, void *data) {
#if 0
        _cleanup_free_ EpollData *e = NULL;

        assert(timeout);

        e = dbus_timeout_get_data(timeout);
        if (!e)
                return;

        assert_se(epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_DEL, e->fd, NULL) >= 0);
        safe_close(e->fd);
#endif
}

static void toggle_timeout(DBusTimeout *timeout, void *data) {
#if 0
        EpollData *e;
        int r;

        assert(timeout);

        e = dbus_timeout_get_data(timeout);
        if (!e)
                return;

        r = timeout_arm(e);
        if (r < 0)
                log_error("Failed to rearm timer: %s", strerror(-r));
#endif
}

int bus_loop_open(DBusConnection *c) {
        int fd;

        assert(c);

        fd = kqueue();
        if (fd < 0)
                return -errno;

        if (!dbus_connection_set_watch_functions(
                    c, add_watch, remove_watch, toggle_watch, INT_TO_PTR(fd), NULL) ||
            !dbus_connection_set_timeout_functions(
                    c, add_timeout, remove_timeout, toggle_timeout, INT_TO_PTR(fd), NULL)) {
                safe_close(fd);
                return -ENOMEM;
        }

        return fd;
}

int bus_loop_dispatch(int fd) {
        int n;
        struct kevent kev = {};
        EpollData *d;

        assert(fd >= 0);

        n = kevent(fd, NULL, 0, &kev, 1, NULL);
        if (n < 0)
                return errno == EAGAIN || errno == EINTR ? 0 : -errno;

        assert_se(d = INT_TO_PTR(kev.udata));

        if (d->is_timeout) {
                DBusTimeout *t = d->object;

                if (dbus_timeout_get_enabled(t))
                        dbus_timeout_handle(t);
        } else {
                DBusWatch *w = d->object;

                if (dbus_watch_get_enabled(w)) {
                        int dbevents;

                        if (kev.filter == EVFILT_WRITE)
                                dbevents |= DBUS_WATCH_WRITABLE;
                        else
                                dbevents |= DBUS_WATCH_READABLE;
                        if (kev.flags & EV_EOF)
                                dbevents |= DBUS_WATCH_HANGUP;
                        if (kev.flags & EV_ERROR)
                                dbevents |= DBUS_WATCH_ERROR;
                        dbus_watch_handle(w, dbevents);
                }
        }

        return 0;
}
