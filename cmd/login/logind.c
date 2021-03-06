/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>

#include "conf-parser.h"
#include "dbus-common.h"
#include "dbus-loop-libev.h"
#include "ev-util.h"
#include "logind.h"
#include "mkdir.h"
#include "strv.h"

#ifdef Use_libudev
#        include <libudev.h>
#endif

#ifdef Sys_Plat_Linux
#        include <linux/vt.h>
#elif defined(Sys_Plat_NetBSD)
#        include <dev/wscons/wsdisplay_usl_io.h>
#endif


Manager *manager_new(void) {
        Manager *m;

        m = new0(Manager, 1);
        if (!m)
                return NULL;

        ev_io_zero(m->console_active_watch);
#ifdef Use_libudev
	ev_io_zero(m->udev_device_watch);
        ev_io_zero(m->udev_seat_watch);
        ev_io_zero(m->udev_vcsa_watch);
        ev_io_zero(m->udev_button_watch);
#endif
        m->reserve_vt_fd = -1;

        m->n_autovts = 6;
        m->reserve_vt = 6;
        m->inhibit_delay_max = 5 * USEC_PER_SEC;
        m->handle_power_key = HANDLE_POWEROFF;
        m->handle_suspend_key = HANDLE_SUSPEND;
        m->handle_hibernate_key = HANDLE_HIBERNATE;
        m->handle_lid_switch = HANDLE_SUSPEND;
        m->lid_switch_ignore_inhibited = true;

        ev_timer_zero(m->idle_action_watch);
        m->idle_action_usec = 30 * USEC_PER_MINUTE;
        m->idle_action = HANDLE_IGNORE;
        m->idle_action_not_before_usec = now(CLOCK_MONOTONIC);

        m->devices = hashmap_new(string_hash_func, string_compare_func);
        m->seats = hashmap_new(string_hash_func, string_compare_func);
        m->sessions = hashmap_new(string_hash_func, string_compare_func);
        m->users = hashmap_new(trivial_hash_func, trivial_compare_func);
        m->inhibitors = hashmap_new(string_hash_func, string_compare_func);
        m->buttons = hashmap_new(string_hash_func, string_compare_func);
        m->busnames = hashmap_new(string_hash_func, string_compare_func);

        m->user_units = hashmap_new(string_hash_func, string_compare_func);
        m->session_units = hashmap_new(string_hash_func, string_compare_func);

        if (!m->devices || !m->seats || !m->sessions || !m->users || !m->inhibitors || !m->buttons ||
            !m->busnames || !m->user_units || !m->session_units) {
                manager_free(m);
                return NULL;
        }

        m->kill_exclude_users = strv_new("root", NULL);
        if (!m->kill_exclude_users) {
                manager_free(m);
                return NULL;
        }

#ifdef Use_libudev
	m->udev = udev_new();
        if (!m->udev) {
                manager_free(m);
                return NULL;
        }
#endif

        return m;
}

void manager_free(Manager *m) {
        Session *session;
        User *u;
        Device *d;
        Seat *s;
        Inhibitor *i;
        Button *b;
        char *n;

        assert(m);

        while ((session = hashmap_first(m->sessions)))
                session_free(session);

        while ((u = hashmap_first(m->users)))
                user_free(u);

        while ((d = hashmap_first(m->devices)))
                device_free(d);

        while ((s = hashmap_first(m->seats)))
                seat_free(s);

        while ((i = hashmap_first(m->inhibitors)))
                inhibitor_free(i);

#ifdef Sys_Plat_Linux // FIXME: evdev
        while ((b = hashmap_first(m->buttons)))
                button_free(b);
#endif

        while ((n = hashmap_first(m->busnames)))
                free(hashmap_remove(m->busnames, n));

        hashmap_free(m->devices);
        hashmap_free(m->seats);
        hashmap_free(m->sessions);
        hashmap_free(m->users);
        hashmap_free(m->inhibitors);
        hashmap_free(m->buttons);
        hashmap_free(m->busnames);

        hashmap_free(m->user_units);
        hashmap_free(m->session_units);

        ev_io_stop_close_zero(m->evloop, &m->console_active_watch);

#ifdef Use_libudev
	if (m->udev_seat_monitor)
                udev_monitor_unref(m->udev_seat_monitor);
        if (m->udev_device_monitor)
                udev_monitor_unref(m->udev_device_monitor);
        if (m->udev_vcsa_monitor)
                udev_monitor_unref(m->udev_vcsa_monitor);
        if (m->udev_button_monitor)
                udev_monitor_unref(m->udev_button_monitor);

        if (m->udev)
                udev_unref(m->udev);
#endif

        if (m->bus) {
                dbus_connection_flush(m->bus);
                dbus_connection_close(m->bus);
                dbus_connection_unref(m->bus);
        }

        ev_timer_stop(m->evloop, &m->idle_action_watch);

        safe_close(m->reserve_vt_fd);

        ev_default_destroy();

        strv_free(m->kill_only_users);
        strv_free(m->kill_exclude_users);

        free(m->action_job);
        free(m);
}

int manager_enumerate_devices(Manager *m) {
#ifdef Use_libudev
	struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(m);

        /* Loads devices from udev and creates seats for them as
         * necessary */

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = udev_enumerate_add_match_tag(e, "master-of-seat");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = manager_process_seat_device(m, d);
                udev_device_unref(d);

                if (k < 0)
                        r = k;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
#else
        return 0;
#endif
}

int manager_enumerate_buttons(Manager *m) {
#ifdef Use_libudev
	struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(m);

        /* Loads buttons from udev */

        if (m->handle_power_key == HANDLE_IGNORE &&
            m->handle_suspend_key == HANDLE_IGNORE &&
            m->handle_hibernate_key == HANDLE_IGNORE &&
            m->handle_lid_switch == HANDLE_IGNORE)
                return 0;

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = udev_enumerate_add_match_subsystem(e, "input");
        if (r < 0)
                goto finish;

        r = udev_enumerate_add_match_tag(e, "power-switch");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = manager_process_button_device(m, d);
                udev_device_unref(d);

                if (k < 0)
                        r = k;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
#else
        return 0;
#endif
}

int manager_enumerate_seats(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

        /* This loads data about seats stored on disk, but does not
         * actually create any seats. Removes data of seats that no
         * longer exist. */

	d = opendir(INSTALL_PKGRUNSTATE_DIR "/seats");
	if (!d) {
                if (errno == ENOENT)
                        return 0;

		log_error("Failed to open " INSTALL_PKGRUNSTATE_DIR "/seats: %m");
		return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                Seat *s;
                int k;

                if (!dirent_is_file(de))
                        continue;

                s = hashmap_get(m->seats, de->d_name);
                if (!s) {
                        unlinkat(dirfd(d), de->d_name, 0);
                        continue;
                }

                k = seat_load(s);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int manager_enumerate_linger_users(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

        d = opendir(AbsDir_PkgVarLib "/linger");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open " AbsDir_PkgVarLib "/linger/: %m");
                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_user_by_name(m, de->d_name, NULL);
                if (k < 0) {
                        log_notice("Couldn't add lingering user %s: %s", de->d_name, strerror(-k));
                        r = k;
                }
        }

        return r;
}

int manager_enumerate_users(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r, k;

        assert(m);

        /* Add lingering users */
        r = manager_enumerate_linger_users(m);

        /* Read in user data stored on disk */
	d = opendir(INSTALL_PKGRUNSTATE_DIR "/users");
	if (!d) {
                if (errno == ENOENT)
                        return 0;

		log_error("Failed to open " INSTALL_PKGRUNSTATE_DIR "/users: %m");
		return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                User *u;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_user_by_name(m, de->d_name, &u);
                if (k < 0) {
                        log_error("Failed to add user by file name %s: %s", de->d_name, strerror(-k));

                        r = k;
                        continue;
                }

                user_add_to_gc_queue(u);

                k = user_load(u);
                if (k < 0)
                        r = k;
        }

        return r;
}

int manager_enumerate_sessions(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

        /* Read in session data stored on disk */
	d = opendir(INSTALL_PKGRUNSTATE_DIR "/sessions");
	if (!d) {
                if (errno == ENOENT)
                        return 0;

		log_error("Failed to open " INSTALL_PKGRUNSTATE_DIR "/sessions: %m");
		return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                struct Session *s;
                int k;

                if (!dirent_is_file(de))
                        continue;

                if (!session_id_valid(de->d_name)) {
                        log_warning("Invalid session file name '%s', ignoring.", de->d_name);
                        r = -EINVAL;
                        continue;
                }

                k = manager_add_session(m, de->d_name, &s);
                if (k < 0) {
                        log_error("Failed to add session by file name %s: %s", de->d_name, strerror(-k));

                        r = k;
                        continue;
                }

                session_add_to_gc_queue(s);

                k = session_load(s);
                if (k < 0)
                        r = k;
        }

        return r;
}

int manager_enumerate_inhibitors(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

	d = opendir(INSTALL_PKGRUNSTATE_DIR "/inhibit");
	if (!d) {
                if (errno == ENOENT)
                        return 0;

		log_error("Failed to open " INSTALL_PKGRUNSTATE_DIR "/inhibit: %m");
		return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                int k;
                Inhibitor *i;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_inhibitor(m, de->d_name, &i);
                if (k < 0) {
                        log_notice("Couldn't add inhibitor %s: %s", de->d_name, strerror(-k));
                        r = k;
                        continue;
                }

                k = inhibitor_load(i);
                if (k < 0)
                        r = k;
        }

        return r;
}

#ifdef Use_libudev
static void manager_dispatch_seat_udev(struct ev_loop *loop, ev_io *watch, int revents)
{
        struct udev_device *d;
        int r;
        Manager *m = watch->data;

        assert(m);

        d = udev_monitor_receive_device(m->udev_seat_monitor);
        if (!d)
                return (void) log_oom();

        r = manager_process_seat_device(m, d);
        udev_device_unref(d);

        if (r < 0)
                log_error("Error dispatching UDev event: %s\n", strerror(-r));
}

static void manager_dispatch_device_udev(struct ev_loop *loop, ev_io *watch, int revents)
{
        struct udev_device *d;
        int r;
        Manager *m = watch->data;

        assert(m);

        d = udev_monitor_receive_device(m->udev_device_monitor);
        if (!d)
                return (void) log_oom();

        r = manager_process_seat_device(m, d);
        udev_device_unref(d);

        if (r < 0)
                log_error("Error dispatching UDev event: %s\n", strerror(-r));
}

static void manager_dispatch_vcsa_udev(struct ev_loop *loop, ev_io *watch, int revents)
{
        struct udev_device *d;
        int r = 0;
        const char *name;
        Manager *m = watch->data;

        assert(m);

        d = udev_monitor_receive_device(m->udev_vcsa_monitor);
        if (!d)
                return (void) log_oom();

        name = udev_device_get_sysname(d);

        /* Whenever a VCSA device is removed try to reallocate our
         * VTs, to make sure our auto VTs never go away. */

        if (name && startswith(name, "vcsa") && streq_ptr(udev_device_get_action(d), "remove"))
                r = seat_preallocate_vts(m->seat0);

        udev_device_unref(d);

        if (r < 0)
                log_error("Error dispatching UDev event: %s\n", strerror(-r));
}

static void manager_dispatch_button_udev(struct ev_loop *loop, ev_io *watch, int revents)
{
        struct udev_device *d;
        int r;
        Manager *m = watch->data;

        assert(m);

        d = udev_monitor_receive_device(m->udev_button_monitor);
        if (!d)
                return (void) log_oom();

        r = manager_process_button_device(m, d);
        udev_device_unref(d);

        if (r < 0)
                log_error("Error dispatching UDev event: %s\n", strerror(-r));
}
#endif

int manager_dispatch_console(Manager *m) {
        assert(m);
        assert(m->seat0);

        seat_read_active_vt(m->seat0);

        return 0;
}

static int manager_reserve_vt(Manager *m) {
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (m->reserve_vt <= 0)
                return 0;

        if (asprintf(&p, "/dev/tty%u", m->reserve_vt) < 0)
                return log_oom();

        m->reserve_vt_fd = open(p, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (m->reserve_vt_fd < 0) {

                /* Don't complain on VT-less systems */
                if (errno != ENOENT)
                        log_warning("Failed to pin reserved VT: %m");
                return -errno;
        }

        return 0;
}

static int manager_connect_bus(Manager *m) {
        DBusError error;
        int r;

        assert(m);
        assert(!m->bus);

        dbus_error_init(&error);

        m->bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!m->bus) {
                log_error("Failed to get system D-Bus connection: %s", bus_error_message(&error));
                r = -ECONNREFUSED;
                goto fail;
        }

        if (!dbus_connection_register_object_path(m->bus, "/org/freedesktop/login1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/seat", &bus_seat_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/session", &bus_session_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/login1/user", &bus_user_vtable, m) ||
            !dbus_connection_add_filter(m->bus, bus_message_filter, m, NULL)) {
                r = log_oom();
                goto fail;
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='"DBUS_INTERFACE_DBUS"',"
                           "member='NameOwnerChanged',"
                           "path='"DBUS_PATH_DBUS"'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for NameOwnerChanged: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='" SCHEDULER_DBUS_BUSNAME "',"
                           "interface='" SCHEDULER_DBUS_INTERFACE_MANAGER "',"
                           "member='JobRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for JobRemoved: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='" SCHEDULER_DBUS_BUSNAME "',"
                           "interface='" SCHEDULER_DBUS_INTERFACE_MANAGER "',"
                           "member='UnitRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for UnitRemoved: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='" SCHEDULER_DBUS_BUSNAME "',"
                           "interface='org.freedesktop.DBus.Properties',"
                           "member='PropertiesChanged'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for PropertiesChanged: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='" SCHEDULER_DBUS_BUSNAME "',"
                           "interface='" SCHEDULER_DBUS_INTERFACE_MANAGER "',"
                           "member='Reloading',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for Reloading: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        r = bus_method_call_with_reply(
                        m->bus,
                        SCHEDULER_DBUS_BUSNAME,
                        "/org/freedesktop/systemd1",
                        SCHEDULER_DBUS_INTERFACE ".Manager",
                        "Subscribe",
                        NULL,
                        &error,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to enable subscription: %s", bus_error(&error, r));
                dbus_error_free(&error);
        }

	r = dbus_bus_request_name(m->bus, SESSIOND_DBUS_BUSNAME, DBUS_NAME_FLAG_DO_NOT_QUEUE,
	    &error);
	if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EIO;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)  {
                log_error("Failed to acquire name.");
                r = -EEXIST;
                goto fail;
        }

        r = bus_loop_open(m->evloop, m->bus);
        if (r < 0)
                goto fail;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

static void console_io_cb(struct ev_loop *evloop, ev_io *watch, int revents)
{
        manager_dispatch_console(watch->data);
}

/* PORTME: */
static int manager_connect_console(Manager *m)
{
        int fd;

        assert(m);
        assert(m->console_active_watch.fd < 0);

        /* On certain architectures (S390 and Xen, and containers),
           /dev/tty0 does not exist, so don't fail if we can't open
           it. */
        if (access("/dev/tty0", F_OK) < 0) {
                m->console_active_watch.fd = -1;
                return 0;
        }

        fd = open("/sys/class/tty/tty0/active", O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0) {

                /* On some systems the device node /dev/tty0 may exist
                 * even though /sys/class/tty/tty0 does not. */
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /sys/class/tty/tty0/active: %m");
                return -errno;
        }

        ev_io_init(&m->console_active_watch, console_io_cb, fd, EV_READ);
        m->console_active_watch.data = m;

        if (ev_io_start(m->evloop, &m->console_active_watch) < 0)
                return -errno;

        return 0;
}

static int manager_connect_udev(Manager *m)
{
#ifdef Use_libudev
	int r;

        assert(m);
        assert(!m->udev_seat_monitor);
        assert(!m->udev_device_monitor);
        assert(!m->udev_vcsa_monitor);
        assert(!m->udev_button_monitor);

        m->udev_seat_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_seat_monitor)
                return -ENOMEM;

#ifdef Sys_Plat_Linux // FIXME: udev
        r = udev_monitor_filter_add_match_tag(m->udev_seat_monitor, "master-of-seat");
        if (r < 0)
                return r;
#endif

        r = udev_monitor_enable_receiving(m->udev_seat_monitor);
        if (r < 0)
                return r;


        ev_io_init(
                &m->udev_seat_watch,
                manager_dispatch_seat_udev,
                udev_monitor_get_fd(m->udev_seat_monitor),
                EV_READ);
        m->udev_seat_watch.data = m;
        if (ev_io_start(m->evloop, &m->udev_seat_watch) < 0)
                return -errno;

        m->udev_device_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_device_monitor)
                return -ENOMEM;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_device_monitor, "input", NULL);
        if (r < 0)
                return r;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_device_monitor, "graphics", NULL);
        if (r < 0)
                return r;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_device_monitor, "drm", NULL);
        if (r < 0)
                return r;

        r = udev_monitor_enable_receiving(m->udev_device_monitor);
        if (r < 0)
                return r;

        ev_io_init(
                &m->udev_device_watch,
                manager_dispatch_device_udev,
                udev_monitor_get_fd(m->udev_device_monitor),
                EV_READ);
        m->udev_device_watch.data = m;
        if (ev_io_start(m->evloop, &m->udev_device_watch) < 0)
                return -errno;

        /* Don't watch keys if nobody cares */
        if (m->handle_power_key != HANDLE_IGNORE ||
            m->handle_suspend_key != HANDLE_IGNORE ||
            m->handle_hibernate_key != HANDLE_IGNORE ||
            m->handle_lid_switch != HANDLE_IGNORE) {

                m->udev_button_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_button_monitor)
                        return -ENOMEM;

#        ifdef Sys_Plat_Linux // FIXME: udev
                r = udev_monitor_filter_add_match_tag(m->udev_button_monitor, "power-switch");
                if (r < 0)
                        return r;
#        endif

                r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_button_monitor, "input", NULL);
                if (r < 0)
                        return r;

                r = udev_monitor_enable_receiving(m->udev_button_monitor);
                if (r < 0)
                        return r;

                ev_io_init(
                        &m->udev_button_watch,
                        manager_dispatch_button_udev,
                        udev_monitor_get_fd(m->udev_button_monitor),
                        EV_READ);
                m->udev_button_watch.data = m;
                if (ev_io_start(m->evloop, &m->udev_button_watch) < 0)
                        return -errno;
        }

        /* Don't bother watching VCSA devices, if nobody cares */
        if (m->n_autovts > 0 && m->console_active_watch.fd >= 0) {

                m->udev_vcsa_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_vcsa_monitor)
                        return -ENOMEM;

                r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_vcsa_monitor, "vc", NULL);
                if (r < 0)
                        return r;

                r = udev_monitor_enable_receiving(m->udev_vcsa_monitor);
                if (r < 0)
                        return r;

                ev_io_init(
                        &m->udev_vcsa_watch,
                        manager_dispatch_vcsa_udev,
                        udev_monitor_get_fd(m->udev_vcsa_monitor),
                        EV_READ);
                m->udev_vcsa_watch.data = m;
                if (ev_io_start(m->evloop, &m->udev_vcsa_watch) < 0)
                        return -errno;
        }

        return 0;
#else
        return 0;
#endif
}

void manager_gc(Manager *m, bool drop_not_started) {
        Seat *seat;
        Session *session;
        User *user;

        assert(m);

        while ((seat = m->seat_gc_queue)) {
                IWLIST_REMOVE(Seat, gc_queue, m->seat_gc_queue, seat);
                seat->in_gc_queue = false;

                if (seat_check_gc(seat, drop_not_started) == 0) {
                        seat_stop(seat);
                        seat_free(seat);
                }
        }

        while ((session = m->session_gc_queue)) {
                IWLIST_REMOVE(Session, gc_queue, m->session_gc_queue, session);
                session->in_gc_queue = false;

                /* First, if we are not closing yet, initiate stopping */
                if (!session_check_gc(session, drop_not_started) &&
                    session_get_state(session) != SESSION_CLOSING)
                        session_stop(session);

                if (!session_check_gc(session, drop_not_started)) {
                        session_finalize(session);
                        session_free(session);
                }
        }

        while ((user = m->user_gc_queue)) {
                IWLIST_REMOVE(User, gc_queue, m->user_gc_queue, user);
                user->in_gc_queue = false;

                if (!user_check_gc(user, drop_not_started) &&
                    user_get_state(user) != USER_CLOSING)
                        user_stop(user);

                if (!user_check_gc(user, drop_not_started)) {
                        user_finalize(user);
                        user_free(user);
                }
        }
}

static void idle_action_timer_cb(struct ev_loop *loop, ev_timer *watch, int revents)
{
        manager_dispatch_idle_action(watch->data);
}

int manager_dispatch_idle_action(Manager *m)
{
	struct dual_timestamp since;
	int r;
        usec_t n;
        ev_tstamp wait_secs;

        assert(m);

        if (m->idle_action == HANDLE_IGNORE || m->idle_action_usec <= 0) {
                return 0;
        }

        n = now(CLOCK_MONOTONIC);

        r = manager_get_idle_hint(m, &since);
        if (r <= 0)
                /* Not idle. Let's check if after a timeout it might be idle then. */
                wait_secs = (n + m->idle_action_usec) / USEC_PER_SEC;
        else {
                /* Idle! Let's see if it's time to do something, or if
                 * we shall sleep for longer. */

                if (n >= since.monotonic + m->idle_action_usec &&
                    (m->idle_action_not_before_usec <= 0 || n >= m->idle_action_not_before_usec + m->idle_action_usec)) {
                        log_info("System idle. Taking action.");

                        manager_handle_action(m, 0, m->idle_action, false, false);
                        m->idle_action_not_before_usec = n;
                }

                wait_secs = (n - MAX(since.monotonic, m->idle_action_not_before_usec) +
                             m->idle_action_usec) /
                        USEC_PER_SEC;
        }

        if (!ev_is_active(&m->idle_action_watch)) {
                ev_init(&m->idle_action_watch, idle_action_timer_cb);
        }

        ev_timer_set(&m->idle_action_watch, 0., wait_secs);
        if (ev_timer_again(m->evloop, &m->idle_action_watch) < 0) {
                log_error("Failed to start timer: %m");
                return -errno;
        }

        return 0;
}

int manager_startup(Manager *m)
{
        int r;
        Seat *seat;
        Session *session;
        User *user;
        Inhibitor *inhibitor;
        Iterator i;

        assert(m);
        assert(m->evloop == NULL);

        m->evloop = ev_default_loop(0);
        if (m->evloop < 0)
                return -ENOMEM;

        /* Connect to console */
        r = manager_connect_console(m);
        if (r < 0)
                return r;

        /* Connect to udev */
        r = manager_connect_udev(m);
        if (r < 0)
                return r;

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Instantiate magic seat 0 */
        r = manager_add_seat(m, "seat0", &m->seat0);
        if (r < 0)
                return r;

        /* Deserialize state */
        r = manager_enumerate_devices(m);
        if (r < 0)
                log_warning("Device enumeration failed: %s", strerror(-r));

        r = manager_enumerate_seats(m);
        if (r < 0)
                log_warning("Seat enumeration failed: %s", strerror(-r));

        r = manager_enumerate_users(m);
        if (r < 0)
                log_warning("User enumeration failed: %s", strerror(-r));

        r = manager_enumerate_sessions(m);
        if (r < 0)
                log_warning("Session enumeration failed: %s", strerror(-r));

        r = manager_enumerate_inhibitors(m);
        if (r < 0)
                log_warning("Inhibitor enumeration failed: %s", strerror(-r));

        r = manager_enumerate_buttons(m);
        if (r < 0)
                log_warning("Button enumeration failed: %s", strerror(-r));

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* Reserve the special reserved VT */
        manager_reserve_vt(m);

        /* And start everything */
        HASHMAP_FOREACH(seat, m->seats, i)
                seat_start(seat);

        HASHMAP_FOREACH(user, m->users, i)
                user_start(user);

        HASHMAP_FOREACH(session, m->sessions, i)
                session_start(session);

        HASHMAP_FOREACH(inhibitor, m->inhibitors, i)
                inhibitor_start(inhibitor);

        manager_dispatch_idle_action(m);

        return 0;
}

static int manager_recheck_buttons(Manager *m) {
        Iterator i;
        Button *b;
        int r = 0;

        assert(m);

#ifdef Sys_Plat_Linux // FIXME: evdev
        HASHMAP_FOREACH(b, m->buttons, i) {
                int q;

                q = button_recheck(b);
                if (q > 0)
                        return 1;
                if (q < 0)
                        r = q;
        }
#endif

        return r;
}

int manager_run(Manager *m) {
        assert(m);

        for (;;) {
                int n;
                int msec = -1;

                manager_gc(m, true);

                if (manager_dispatch_delayed(m) > 0)
                        continue;

                if (manager_recheck_buttons(m) > 0)
                        continue;

                if (dbus_connection_dispatch(m->bus) != DBUS_DISPATCH_COMPLETE)
                        continue;

                manager_gc(m, true);

                if (m->action_what != 0 && !m->action_job) {
                        usec_t x, y;

                        x = now(CLOCK_MONOTONIC);
                        y = m->action_timestamp + m->inhibit_delay_max;

                        msec = x >= y ? 0 : (int) ((y - x) / USEC_PER_MSEC);
                }

                n = ev_run(m->evloop, EVRUN_ONCE);
                if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("ev_run failed: %s", strerror(-n));
                        return -errno;
                }
        }

        return 0;
}

static int manager_parse_config_file(Manager *m) {
	static const char fn[] = INSTALL_PKGSYSCONF_DIR "/logind.conf";
	_cleanup_fclose_ FILE *f = NULL;
	int r;

        assert(m);

        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file %s: %m", fn);
                return -errno;
        }

        r = config_parse(NULL, fn, f, "Login\0", config_item_perf_lookup,
                         (void*) logind_gperf_lookup, false, false, m);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return r;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_set_facility(LOG_AUTH);
        log_parse_environment();
        log_open();
        log_set_max_level(LOG_DEBUG);

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

	/* Always create the directories people can create inotify
         * watches in. Note that some applications might check for the
         * existence of @INSTALL_PKGRUNSTATE_DIR@/seats/ to determine whether
         * logind is available, so please always make sure this check
         * stays in. */
	mkdir_label(INSTALL_PKGRUNSTATE_DIR "/seats", 0755);
	mkdir_label(INSTALL_PKGRUNSTATE_DIR "/users", 0755);
	mkdir_label(INSTALL_PKGRUNSTATE_DIR "/sessions", 0755);

	m = manager_new();
        if (!m) {
                r = log_oom();
                goto finish;
        }

        manager_parse_config_file(m);

        r = manager_startup(m);
        if (r < 0) {
                log_error("Failed to fully start up daemon: %s", strerror(-r));
                goto finish;
        }

        log_debug("systemd-logind running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = manager_run(m);

        log_debug("systemd-logind stopped as pid %lu", (unsigned long) getpid());

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        if (m)
                manager_free(m);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
