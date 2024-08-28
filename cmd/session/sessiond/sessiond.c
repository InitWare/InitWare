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

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "conf-parser.h"
#include "label.h"
#include "logind.h"
#include "mkdir.h"
#include "sd-daemon.h"
#include "strv.h"
#include "udev-util.h"

#ifdef SVC_HAVE_evdev
#include <linux/vt.h>
#endif

#ifdef SVC_HAVE_libudev
#include <libudev.h>
#endif

Manager *
manager_new(void)
{
	Manager *m;
	int r;

	m = new0(Manager, 1);
	if (!m)
		return NULL;

	m->console_active_fd = -1;
	m->reserve_vt_fd = -1;

	m->n_autovts = 6;
	m->reserve_vt = 6;
	m->remove_ipc = false;
	m->inhibit_delay_max = 5 * USEC_PER_SEC;
	m->handle_power_key = HANDLE_POWEROFF;
	m->handle_suspend_key = HANDLE_SUSPEND;
	m->handle_hibernate_key = HANDLE_HIBERNATE;
	m->handle_lid_switch = HANDLE_SUSPEND;
	m->handle_lid_switch_docked = HANDLE_IGNORE;
	m->lid_switch_ignore_inhibited = true;

	m->idle_action_usec = 30 * USEC_PER_MINUTE;
	m->idle_action = HANDLE_IGNORE;
	m->idle_action_not_before_usec = now(CLOCK_MONOTONIC);

	m->runtime_dir_size = PAGE_ALIGN(
		(size_t)(physical_memory() / 10)); /* 10% */
	m->user_tasks_max = (uint64_t)-1;

	m->devices = hashmap_new(&string_hash_ops);
	m->seats = hashmap_new(&string_hash_ops);
	m->sessions = hashmap_new(&string_hash_ops);
	m->users = hashmap_new(NULL);
	m->inhibitors = hashmap_new(&string_hash_ops);
	m->buttons = hashmap_new(&string_hash_ops);

	m->user_units = hashmap_new(&string_hash_ops);
	m->session_units = hashmap_new(&string_hash_ops);

	m->busnames = set_new(&string_hash_ops);

	if (!m->devices || !m->seats || !m->sessions || !m->users ||
		!m->inhibitors || !m->buttons || !m->busnames ||
		!m->user_units || !m->session_units)
		goto fail;

	m->kill_exclude_users = strv_new("root", NULL);
	if (!m->kill_exclude_users)
		goto fail;

#ifdef SVC_HAVE_libudev
	m->udev = udev_new();
	if (!m->udev)
		goto fail;
#endif

	r = sd_event_default(&m->event);
	if (r < 0)
		goto fail;

#ifdef SVC_PLATFORM_Linux
	sd_event_set_watchdog(m->event, true);
#endif

	return m;

fail:
	manager_free(m);
	return NULL;
}

void
manager_free(Manager *m)
{
	Session *session;
	User *u;
	Device *d;
	Seat *s;
	Inhibitor *i;
	Button *b;

	assert(m);

	while ((session = hashmap_first(m->sessions)))
		session_free(session);

	while ((u = hashmap_first(m->users)))
		user_free(u);

#ifdef SVC_HAVE_libudev
	while ((d = hashmap_first(m->devices)))
		device_free(d);
#endif

	while ((s = hashmap_first(m->seats)))
		seat_free(s);

	while ((i = hashmap_first(m->inhibitors)))
		inhibitor_free(i);

#ifdef SVC_HAVE_libudev
	while ((b = hashmap_first(m->buttons)))
		button_free(b);
#endif

	hashmap_free(m->devices);
	hashmap_free(m->seats);
	hashmap_free(m->sessions);
	hashmap_free(m->users);
	hashmap_free(m->inhibitors);
	hashmap_free(m->buttons);

	hashmap_free(m->user_units);
	hashmap_free(m->session_units);

	set_free_free(m->busnames);

	sd_event_source_unref(m->idle_action_event_source);

	sd_event_source_unref(m->console_active_event_source);
#ifdef SVC_HAVE_libudev
	sd_event_source_unref(m->udev_seat_event_source);
	sd_event_source_unref(m->udev_device_event_source);
	sd_event_source_unref(m->udev_vcsa_event_source);
	sd_event_source_unref(m->udev_button_event_source);
#endif
	sd_event_source_unref(m->lid_switch_ignore_event_source);

	safe_close(m->console_active_fd);

#ifdef SVC_HAVE_libudev
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

	bus_verify_polkit_async_registry_free(m->polkit_registry);

	sd_bus_unref(m->bus);
	sd_event_unref(m->event);

	safe_close(m->reserve_vt_fd);

	strv_free(m->kill_only_users);
	strv_free(m->kill_exclude_users);

	free(m->action_job);
	free(m);
}

static int
manager_enumerate_devices(Manager *m)
{
#ifdef SVC_HAVE_libudev
	struct udev_list_entry *item = NULL, *first = NULL;
	_cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
	int r;

	assert(m);

	/* Loads devices from udev and creates seats for them as
         * necessary */

	e = udev_enumerate_new(m->udev);
	if (!e)
		return -ENOMEM;

	r = udev_enumerate_add_match_tag(e, "master-of-seat");
	if (r < 0)
		return r;

	r = udev_enumerate_add_match_is_initialized(e);
	if (r < 0)
		return r;

	r = udev_enumerate_scan_devices(e);
	if (r < 0)
		return r;

	first = udev_enumerate_get_list_entry(e);
	udev_list_entry_foreach(item, first)
	{
		_cleanup_udev_device_unref_ struct udev_device *d = NULL;
		int k;

		d = udev_device_new_from_syspath(m->udev,
			udev_list_entry_get_name(item));
		if (!d)
			return -ENOMEM;

		k = manager_process_seat_device(m, d);
		if (k < 0)
			r = k;
	}

	return r;
#else
	return 0;
#endif
}

static int
manager_enumerate_buttons(Manager *m)
{
#if defined(SVC_HAVE_libudev) && defined(SVC_HAVE_evdev)
	_cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
	struct udev_list_entry *item = NULL, *first = NULL;
	int r;

	assert(m);

	/* Loads buttons from udev */

	if (m->handle_power_key == HANDLE_IGNORE &&
		m->handle_suspend_key == HANDLE_IGNORE &&
		m->handle_hibernate_key == HANDLE_IGNORE &&
		m->handle_lid_switch == HANDLE_IGNORE &&
		m->handle_lid_switch_docked == HANDLE_IGNORE)
		return 0;

	e = udev_enumerate_new(m->udev);
	if (!e)
		return -ENOMEM;

	r = udev_enumerate_add_match_subsystem(e, "input");
	if (r < 0)
		return r;

	r = udev_enumerate_add_match_tag(e, "power-switch");
	if (r < 0)
		return r;

	r = udev_enumerate_add_match_is_initialized(e);
	if (r < 0)
		return r;

	r = udev_enumerate_scan_devices(e);
	if (r < 0)
		return r;

	first = udev_enumerate_get_list_entry(e);
	udev_list_entry_foreach(item, first)
	{
		_cleanup_udev_device_unref_ struct udev_device *d = NULL;
		int k;

		d = udev_device_new_from_syspath(m->udev,
			udev_list_entry_get_name(item));
		if (!d)
			return -ENOMEM;

		k = manager_process_button_device(m, d);
		if (k < 0)
			r = k;
	}

	return r;
#else
	return 0;
#endif
}

static int
manager_enumerate_seats(Manager *m)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;

	assert(m);

	/* This loads data about seats stored on disk, but does not
         * actually create any seats. Removes data of seats that no
         * longer exist. */

	d = opendir(SVC_PKGRUNSTATEDIR "/seats");
	if (!d) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open " SVC_PKGRUNSTATEDIR "/seats: %m");
		return -errno;
	}

	FOREACH_DIRENT (de, d, return -errno) {
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

static int
manager_enumerate_linger_users(Manager *m)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;

	assert(m);

	d = opendir(SVC_PKGLOCALSTATEDIR "/linger");
	if (!d) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open " SVC_PKGLOCALSTATEDIR "/linger/: %m");
		return -errno;
	}

	FOREACH_DIRENT (de, d, return -errno) {
		int k;

		if (!dirent_is_file(de))
			continue;

		k = manager_add_user_by_name(m, de->d_name, NULL);
		if (k < 0) {
			log_notice_errno(k,
				"Couldn't add lingering user %s: %m",
				de->d_name);
			r = k;
		}
	}

	return r;
}

static int
manager_enumerate_users(Manager *m)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r, k;

	assert(m);

	/* Add lingering users */
	r = manager_enumerate_linger_users(m);

	/* Read in user data stored on disk */
	d = opendir(SVC_PKGRUNSTATEDIR "/users");
	if (!d) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open " SVC_PKGRUNSTATEDIR "/users: %m");
		return -errno;
	}

	FOREACH_DIRENT (de, d, return -errno) {
		User *u;

		if (!dirent_is_file(de))
			continue;

		k = manager_add_user_by_name(m, de->d_name, &u);
		if (k < 0) {
			log_error_errno(k,
				"Failed to add user by file name %s: %m",
				de->d_name);

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

static int
manager_enumerate_sessions(Manager *m)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;

	assert(m);

	/* Read in session data stored on disk */
	d = opendir(SVC_PKGRUNSTATEDIR "/sessions");
	if (!d) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open " SVC_PKGRUNSTATEDIR "/sessions: %m");
		return -errno;
	}

	FOREACH_DIRENT (de, d, return -errno) {
		struct Session *s;
		int k;

		if (!dirent_is_file(de))
			continue;

		if (!session_id_valid(de->d_name)) {
			log_warning("Invalid session file name '%s', ignoring.",
				de->d_name);
			r = -EINVAL;
			continue;
		}

		k = manager_add_session(m, de->d_name, &s);
		if (k < 0) {
			log_error_errno(k,
				"Failed to add session by file name %s: %m",
				de->d_name);

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

static int
manager_enumerate_inhibitors(Manager *m)
{
	_cleanup_closedir_ DIR *d = NULL;
	struct dirent *de;
	int r = 0;

	assert(m);

	d = opendir(SVC_PKGRUNSTATEDIR "/inhibit");
	if (!d) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open " SVC_PKGRUNSTATEDIR "/inhibit: %m");
		return -errno;
	}

	FOREACH_DIRENT (de, d, return -errno) {
		int k;
		Inhibitor *i;

		if (!dirent_is_file(de))
			continue;

		k = manager_add_inhibitor(m, de->d_name, &i);
		if (k < 0) {
			log_notice_errno(k, "Couldn't add inhibitor %s: %m",
				de->d_name);
			r = k;
			continue;
		}

		k = inhibitor_load(i);
		if (k < 0)
			r = k;
	}

	return r;
}

#ifdef SVC_HAVE_libudev
static int
manager_dispatch_seat_udev(sd_event_source *s, int fd, uint32_t revents,
	void *userdata)
{
	_cleanup_udev_device_unref_ struct udev_device *d = NULL;
	Manager *m = userdata;

	assert(m);

	d = udev_monitor_receive_device(m->udev_seat_monitor);
	if (!d)
		return -ENOMEM;

	manager_process_seat_device(m, d);
	return 0;
}

static int
manager_dispatch_device_udev(sd_event_source *s, int fd, uint32_t revents,
	void *userdata)
{
	_cleanup_udev_device_unref_ struct udev_device *d = NULL;
	Manager *m = userdata;

	assert(m);

	d = udev_monitor_receive_device(m->udev_device_monitor);
	if (!d)
		return -ENOMEM;

	manager_process_seat_device(m, d);
	return 0;
}

static int
manager_dispatch_vcsa_udev(sd_event_source *s, int fd, uint32_t revents,
	void *userdata)
{
	_cleanup_udev_device_unref_ struct udev_device *d = NULL;
	Manager *m = userdata;
	const char *name;

	assert(m);

	d = udev_monitor_receive_device(m->udev_vcsa_monitor);
	if (!d)
		return -ENOMEM;

	name = udev_device_get_sysname(d);

	/* Whenever a VCSA device is removed try to reallocate our
         * VTs, to make sure our auto VTs never go away. */

	if (name && startswith(name, "vcsa") &&
		streq_ptr(udev_device_get_action(d), "remove"))
		seat_preallocate_vts(m->seat0);

	return 0;
}

static int
manager_dispatch_button_udev(sd_event_source *s, int fd, uint32_t revents,
	void *userdata)
{
	_cleanup_udev_device_unref_ struct udev_device *d = NULL;
	Manager *m = userdata;

	assert(m);

	d = udev_monitor_receive_device(m->udev_button_monitor);
	if (!d)
		return -ENOMEM;

	manager_process_button_device(m, d);
	return 0;
}
#endif

static int
manager_dispatch_console(sd_event_source *s, int fd, uint32_t revents,
	void *userdata)
{
	Manager *m = userdata;

	assert(m);
	assert(m->seat0);
	assert(m->console_active_fd == fd);

	seat_read_active_vt(m->seat0);
	return 0;
}

static int
manager_reserve_vt(Manager *m)
{
	_cleanup_free_ char *p = NULL;

	assert(m);

	if (m->reserve_vt <= 0)
		return 0;

	if (asprintf(&p, "/dev/tty%u", m->reserve_vt) < 0)
		return log_oom();

	m->reserve_vt_fd = open(p, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
	if (m->reserve_vt_fd < 0) {
		/* Don't complain on VT-less systems */
		if (errno != ENOENT)
			log_warning_errno(errno,
				"Failed to pin reserved VT: %m");
		return -errno;
	}

	return 0;
}

static int
manager_connect_bus(Manager *m)
{
	_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
	int r;

	assert(m);
	assert(!m->bus);

	r = sd_bus_default_system(&m->bus);
	if (r < 0)
		return log_error_errno(r,
			"Failed to connect to system bus: %m");

	r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/login1",
		SVC_SESSIOND_DBUS_INTERFACE ".Manager", manager_vtable, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add manager object vtable: %m");

	r = sd_bus_add_fallback_vtable(m->bus, NULL,
		"/org/freedesktop/login1/seat",
		SVC_SESSIOND_DBUS_INTERFACE ".Seat", seat_vtable,
		seat_object_find, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add seat object vtable: %m");

	r = sd_bus_add_node_enumerator(m->bus, NULL,
		"/org/freedesktop/login1/seat", seat_node_enumerator, m);
	if (r < 0)
		return log_error_errno(r, "Failed to add seat enumerator: %m");

	r = sd_bus_add_fallback_vtable(m->bus, NULL,
		"/org/freedesktop/login1/session",
		SVC_SESSIOND_DBUS_INTERFACE ".Session", session_vtable,
		session_object_find, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add session object vtable: %m");

	r = sd_bus_add_node_enumerator(m->bus, NULL,
		"/org/freedesktop/login1/session", session_node_enumerator, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add session enumerator: %m");

	r = sd_bus_add_fallback_vtable(m->bus, NULL,
		"/org/freedesktop/login1/user",
		SVC_SESSIOND_DBUS_INTERFACE ".User", user_vtable,
		user_object_find, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add user object vtable: %m");

	r = sd_bus_add_node_enumerator(m->bus, NULL,
		"/org/freedesktop/login1/user", user_node_enumerator, m);
	if (r < 0)
		return log_error_errno(r, "Failed to add user enumerator: %m");

	r = sd_bus_add_match(m->bus, NULL,
		"type='signal',"
		"sender='org.freedesktop.DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"path='/org/freedesktop/DBus'",
		match_name_owner_changed, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add match for NameOwnerChanged: %m");

	r = sd_bus_add_match(m->bus, NULL,
		"type='signal',"
		"sender='" SVC_DBUS_BUSNAME "',"
		"interface='" SVC_DBUS_INTERFACE ".Manager',"
		"member='JobRemoved',"
		"path='/org/freedesktop/systemd1'",
		match_job_removed, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add match for JobRemoved: %m");

	r = sd_bus_add_match(m->bus, NULL,
		"type='signal',"
		"sender='" SVC_DBUS_BUSNAME "',"
		"interface='" SVC_DBUS_INTERFACE ".Manager',"
		"member='UnitRemoved',"
		"path='/org/freedesktop/systemd1'",
		match_unit_removed, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add match for UnitRemoved: %m");

	r = sd_bus_add_match(m->bus, NULL,
		"type='signal',"
		"sender='" SVC_DBUS_BUSNAME "',"
		"interface='org.freedesktop.DBus.Properties',"
		"member='PropertiesChanged'",
		match_properties_changed, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add match for PropertiesChanged: %m");

	r = sd_bus_add_match(m->bus, NULL,
		"type='signal',"
		"sender='" SVC_DBUS_BUSNAME "',"
		"interface='" SVC_DBUS_INTERFACE ".Manager',"
		"member='Reloading',"
		"path='/org/freedesktop/systemd1'",
		match_reloading, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add match for Reloading: %m");

	r = sd_bus_call_method(m->bus, SVC_DBUS_BUSNAME,
		"/org/freedesktop/systemd1", SVC_DBUS_INTERFACE ".Manager",
		"Subscribe", &error, NULL, NULL);
	if (r < 0) {
		log_error("Failed to enable subscription: %s",
			bus_error_message(&error, r));
		return r;
	}

	r = sd_bus_request_name(m->bus, SVC_SESSIOND_DBUS_BUSNAME, 0);
	if (r < 0)
		return log_error_errno(r, "Failed to register name: %m");

	r = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
	if (r < 0)
		return log_error_errno(r,
			"Failed to attach bus to event loop: %m");

	return 0;
}

static int
manager_vt_switch(sd_event_source *src, const struct sigfd_siginfo *si,
	void *data)
{
	Manager *m = data;
	Session *active, *iter;

	/*
         * We got a VT-switch signal and we have to acknowledge it immediately.
         * Preferably, we'd just use m->seat0->active->vtfd, but unfortunately,
         * old user-space might run multiple sessions on a single VT, *sigh*.
         * Therefore, we have to iterate all sessions and find one with a vtfd
         * on the requested VT.
         * As only VTs with active controllers have VT_PROCESS set, our current
         * notion of the active VT might be wrong (for instance if the switch
         * happens while we setup VT_PROCESS). Therefore, read the current VT
         * first and then use s->active->vtnr as reference. Note that this is
         * not racy, as no further VT-switch can happen as long as we're in
         * synchronous VT_PROCESS mode.
         */

	assert(m->seat0);
	seat_read_active_vt(m->seat0);

	active = m->seat0->active;
	if (!active || active->vtnr < 1) {
		log_warning(
			"Received VT_PROCESS signal without a registered session on that VT.");
		return 0;
	}

	if (active->vtfd >= 0) {
		session_leave_vt(active);
	} else {
		IWLIST_FOREACH (sessions_by_seat, iter, m->seat0->sessions) {
			if (iter->vtnr == active->vtnr && iter->vtfd >= 0) {
				session_leave_vt(iter);
				break;
			}
		}
	}

	return 0;
}

static int
manager_connect_console(Manager *m)
{
	int r;

	assert(m);
	assert(m->console_active_fd < 0);

	/* On certain architectures (S390 and Xen, and containers),
           /dev/tty0 does not exist, so don't fail if we can't open
           it. */
	if (access("/dev/tty0", F_OK) < 0)
		return 0;

	m->console_active_fd = open("/sys/class/tty/tty0/active",
		O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (m->console_active_fd < 0) {
		/* On some systems the device node /dev/tty0 may exist
                 * even though /sys/class/tty/tty0 does not. */
		if (errno == ENOENT)
			return 0;

		log_error_errno(errno,
			"Failed to open /sys/class/tty/tty0/active: %m");
		return -errno;
	}

	r = sd_event_add_io(m->event, &m->console_active_event_source,
		m->console_active_fd, 0, manager_dispatch_console, m);
	if (r < 0) {
		log_error("Failed to watch foreground console");
		return r;
	}

#ifdef SIGRTMIN // FIXME: see comment
	/*
         * SIGRTMIN is used as global VT-release signal, SIGRTMIN + 1 is used
         * as VT-acquire signal. We ignore any acquire-events (yes, we still
         * have to provide a valid signal-number for it!) and acknowledge all
         * release events immediately.
         */

	if (SIGRTMIN + 1 > SIGRTMAX) {
		log_error("Not enough real-time signals available: %u-%u",
			SIGRTMIN, SIGRTMAX);
		return -EINVAL;
	}

	r = ignore_signals(SIGRTMIN + 1, -1);
	if (r < 0)
		return log_error_errno(r, "Cannot ignore SIGRTMIN + 1: %m");

	r = sigprocmask_many(SIG_BLOCK, SIGRTMIN, -1);
	if (r < 0)
		return log_error_errno(r, "Cannot block SIGRTMIN: %m");

	r = sd_event_add_signal(m->event, NULL, SIGRTMIN, manager_vt_switch, m);
	if (r < 0)
		return r;
#endif

	return 0;
}

static int
manager_connect_udev(Manager *m)
{
#ifdef SVC_HAVE_libudev
	int r;

	assert(m);
	assert(!m->udev_seat_monitor);
	assert(!m->udev_device_monitor);
	assert(!m->udev_vcsa_monitor);
	assert(!m->udev_button_monitor);

	m->udev_seat_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
	if (!m->udev_seat_monitor)
		return -ENOMEM;

	r = udev_monitor_filter_add_match_tag(m->udev_seat_monitor,
		"master-of-seat");
	if (r < 0)
		return r;

	r = udev_monitor_enable_receiving(m->udev_seat_monitor);
	if (r < 0)
		return r;

	r = sd_event_add_io(m->event, &m->udev_seat_event_source,
		udev_monitor_get_fd(m->udev_seat_monitor), EPOLLIN,
		manager_dispatch_seat_udev, m);
	if (r < 0)
		return r;

	m->udev_device_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
	if (!m->udev_device_monitor)
		return -ENOMEM;

	r = udev_monitor_filter_add_match_subsystem_devtype(
		m->udev_device_monitor, "input", NULL);
	if (r < 0)
		return r;

	r = udev_monitor_filter_add_match_subsystem_devtype(
		m->udev_device_monitor, "graphics", NULL);
	if (r < 0)
		return r;

	r = udev_monitor_filter_add_match_subsystem_devtype(
		m->udev_device_monitor, "drm", NULL);
	if (r < 0)
		return r;

	r = udev_monitor_enable_receiving(m->udev_device_monitor);
	if (r < 0)
		return r;

	r = sd_event_add_io(m->event, &m->udev_device_event_source,
		udev_monitor_get_fd(m->udev_device_monitor), EPOLLIN,
		manager_dispatch_device_udev, m);
	if (r < 0)
		return r;

	/* Don't watch keys if nobody cares */
	if (m->handle_power_key != HANDLE_IGNORE ||
		m->handle_suspend_key != HANDLE_IGNORE ||
		m->handle_hibernate_key != HANDLE_IGNORE ||
		m->handle_lid_switch != HANDLE_IGNORE ||
		m->handle_lid_switch_docked != HANDLE_IGNORE) {
		m->udev_button_monitor = udev_monitor_new_from_netlink(m->udev,
			"udev");
		if (!m->udev_button_monitor)
			return -ENOMEM;

		r = udev_monitor_filter_add_match_tag(m->udev_button_monitor,
			"power-switch");
		if (r < 0)
			return r;

		r = udev_monitor_filter_add_match_subsystem_devtype(
			m->udev_button_monitor, "input", NULL);
		if (r < 0)
			return r;

		r = udev_monitor_enable_receiving(m->udev_button_monitor);
		if (r < 0)
			return r;

		r = sd_event_add_io(m->event, &m->udev_button_event_source,
			udev_monitor_get_fd(m->udev_button_monitor), EPOLLIN,
			manager_dispatch_button_udev, m);
		if (r < 0)
			return r;
	}

	/* Don't bother watching VCSA devices, if nobody cares */
	if (m->n_autovts > 0 && m->console_active_fd >= 0) {
		m->udev_vcsa_monitor = udev_monitor_new_from_netlink(m->udev,
			"udev");
		if (!m->udev_vcsa_monitor)
			return -ENOMEM;

		r = udev_monitor_filter_add_match_subsystem_devtype(
			m->udev_vcsa_monitor, "vc", NULL);
		if (r < 0)
			return r;

		r = udev_monitor_enable_receiving(m->udev_vcsa_monitor);
		if (r < 0)
			return r;

		r = sd_event_add_io(m->event, &m->udev_vcsa_event_source,
			udev_monitor_get_fd(m->udev_vcsa_monitor), EPOLLIN,
			manager_dispatch_vcsa_udev, m);
		if (r < 0)
			return r;
	}

	return 0;
#else
	return 0;
#endif
}

void
manager_gc(Manager *m, bool drop_not_started)
{
	Seat *seat;
	Session *session;
	User *user;

	assert(m);

	while ((seat = m->seat_gc_queue)) {
		IWLIST_REMOVE(gc_queue, m->seat_gc_queue, seat);
		seat->in_gc_queue = false;

		if (!seat_check_gc(seat, drop_not_started)) {
			seat_stop(seat, false);
			seat_free(seat);
		}
	}

	while ((session = m->session_gc_queue)) {
		IWLIST_REMOVE(gc_queue, m->session_gc_queue, session);
		session->in_gc_queue = false;

		/* First, if we are not closing yet, initiate stopping */
		if (!session_check_gc(session, drop_not_started) &&
			session_get_state(session) != SESSION_CLOSING)
			session_stop(session, false);

		/* Normally, this should make the session busy again,
                 * if it doesn't then let's get rid of it
                 * immediately */
		if (!session_check_gc(session, drop_not_started)) {
			session_finalize(session);
			session_free(session);
		}
	}

	while ((user = m->user_gc_queue)) {
		IWLIST_REMOVE(gc_queue, m->user_gc_queue, user);
		user->in_gc_queue = false;

		/* First step: queue stop jobs */
		if (!user_check_gc(user, drop_not_started))
			user_stop(user, false);

		/* Second step: finalize user */
		if (!user_check_gc(user, drop_not_started)) {
			user_finalize(user);
			user_free(user);
		}
	}
}

static int
manager_dispatch_idle_action(sd_event_source *s, uint64_t t, void *userdata)
{
	Manager *m = userdata;
	struct dual_timestamp since;
	usec_t n, elapse;
	int r;

	assert(m);

	if (m->idle_action == HANDLE_IGNORE || m->idle_action_usec <= 0)
		return 0;

	n = now(CLOCK_MONOTONIC);

	r = manager_get_idle_hint(m, &since);
	if (r <= 0)
		/* Not idle. Let's check if after a timeout it might be idle then. */
		elapse = n + m->idle_action_usec;
	else {
		/* Idle! Let's see if it's time to do something, or if
                 * we shall sleep for longer. */

		if (n >= since.monotonic + m->idle_action_usec &&
			(m->idle_action_not_before_usec <= 0 ||
				n >= m->idle_action_not_before_usec +
						m->idle_action_usec)) {
			log_info("System idle. Taking action.");

			manager_handle_action(m, 0, m->idle_action, false,
				false);
			m->idle_action_not_before_usec = n;
		}

		elapse = MAX(since.monotonic, m->idle_action_not_before_usec) +
			m->idle_action_usec;
	}

	if (!m->idle_action_event_source) {
		r = sd_event_add_time(m->event, &m->idle_action_event_source,
			CLOCK_MONOTONIC, elapse, USEC_PER_SEC * 30,
			manager_dispatch_idle_action, m);
		if (r < 0)
			return log_error_errno(r,
				"Failed to add idle event source: %m");

		r = sd_event_source_set_priority(m->idle_action_event_source,
			SD_EVENT_PRIORITY_IDLE + 10);
		if (r < 0)
			return log_error_errno(r,
				"Failed to set idle event source priority: %m");
	} else {
		r = sd_event_source_set_time(m->idle_action_event_source,
			elapse);
		if (r < 0)
			return log_error_errno(r,
				"Failed to set idle event timer: %m");

		r = sd_event_source_set_enabled(m->idle_action_event_source,
			SD_EVENT_ONESHOT);
		if (r < 0)
			return log_error_errno(r,
				"Failed to enable idle event timer: %m");
	}

	return 0;
}

int
manager_startup(Manager *m)
{
	int r;
	Seat *seat;
	Session *session;
	User *user;
	Button *button;
	Inhibitor *inhibitor;
	Iterator i;

	assert(m);

	/* Connect to console */
	r = manager_connect_console(m);
	if (r < 0)
		return r;

	/* Connect to udev */
	r = manager_connect_udev(m);
	if (r < 0)
		return log_error_errno(r, "Failed to create udev watchers: %m");

	/* Connect to the bus */
	r = manager_connect_bus(m);
	if (r < 0)
		return r;

	/* Instantiate magic seat 0 */
	r = manager_add_seat(m, "seat0", &m->seat0);
	if (r < 0)
		return log_error_errno(r, "Failed to add seat0: %m");

	r = manager_set_lid_switch_ignore(m,
		0 + IGNORE_LID_SWITCH_STARTUP_USEC);
	if (r < 0)
		log_warning_errno(r,
			"Failed to set up lid switch ignore event source: %m");

	/* Deserialize state */
	r = manager_enumerate_devices(m);
	if (r < 0)
		log_warning_errno(r, "Device enumeration failed: %m");

	r = manager_enumerate_seats(m);
	if (r < 0)
		log_warning_errno(r, "Seat enumeration failed: %m");

	r = manager_enumerate_users(m);
	if (r < 0)
		log_warning_errno(r, "User enumeration failed: %m");

	r = manager_enumerate_sessions(m);
	if (r < 0)
		log_warning_errno(r, "Session enumeration failed: %m");

	r = manager_enumerate_inhibitors(m);
	if (r < 0)
		log_warning_errno(r, "Inhibitor enumeration failed: %m");

	r = manager_enumerate_buttons(m);
	if (r < 0)
		log_warning_errno(r, "Button enumeration failed: %m");

	/* Remove stale objects before we start them */
	manager_gc(m, false);

	/* Reserve the special reserved VT */
	manager_reserve_vt(m);

	/* And start everything */
	HASHMAP_FOREACH (seat, m->seats, i)
		seat_start(seat);

	HASHMAP_FOREACH (user, m->users, i)
		user_start(user);

	HASHMAP_FOREACH (session, m->sessions, i)
		session_start(session);

	HASHMAP_FOREACH (inhibitor, m->inhibitors, i)
		inhibitor_start(inhibitor);

#ifdef SVC_HAVE_evdev
	HASHMAP_FOREACH (button, m->buttons, i)
		button_check_switches(button);
#endif

	manager_dispatch_idle_action(NULL, 0, m);

	return 0;
}

int
manager_run(Manager *m)
{
	int r;

	assert(m);

	for (;;) {
		usec_t us = (uint64_t)-1;

		r = sd_event_get_state(m->event);
		if (r < 0)
			return r;
		if (r == SD_EVENT_FINISHED)
			return 0;

		manager_gc(m, true);

		if (manager_dispatch_delayed(m) > 0)
			continue;

		if (m->action_what != 0 && !m->action_job) {
			usec_t x, y;

			x = now(CLOCK_MONOTONIC);
			y = m->action_timestamp + m->inhibit_delay_max;

			us = x >= y ? 0 : y - x;
		}

		r = sd_event_run(m->event, us);
		if (r < 0)
			return r;
	}
}

static int
manager_parse_config_file(Manager *m)
{
	assert(m);

	return config_parse_many(SVC_PKGSYSCONFDIR "/logind.conf",
		CONF_DIRS_NULSTR(SVC_PKGDIRNAME "/logind.conf"), "Login\0",
		config_item_perf_lookup, logind_gperf_lookup, false, m);
}

int
main(int argc, char *argv[])
{
	Manager *m = NULL;
	int r;

	log_set_target(LOG_TARGET_AUTO);
	log_set_facility(LOG_AUTH);
	log_parse_environment();
	log_open();

	umask(0022);

	if (argc != 1) {
		log_error("This program takes no arguments.");
		r = -EINVAL;
		goto finish;
	}

	/* Always create the directories people can create inotify
         * watches in. Note that some applications might check for the
         * existence of $SVC_PKGRUNSTATEDIR/seats/ to determine whether
         * logind is available, so please always make sure this check
         * stays in. */
	mkdir_label(SVC_PKGRUNSTATEDIR "/seats", 0755);
	mkdir_label(SVC_PKGRUNSTATEDIR "/users", 0755);
	mkdir_label(SVC_PKGRUNSTATEDIR "/sessions", 0755);

	m = manager_new();
	if (!m) {
		r = log_oom();
		goto finish;
	}

	manager_parse_config_file(m);

	r = manager_startup(m);
	if (r < 0) {
		log_error_errno(r, "Failed to fully start up daemon: %m");
		goto finish;
	}

	log_debug("systemd-logind running as pid " PID_FMT, getpid());

	sd_notify(false,
		"READY=1\n"
		"STATUS=Processing requests...");

	r = manager_run(m);

	log_debug("systemd-logind stopped as pid " PID_FMT, getpid());

finish:
	sd_notify(false,
		"STOPPING=1\n"
		"STATUS=Shutting down...");

	if (m)
		manager_free(m);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
