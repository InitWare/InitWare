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

#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bsdcapability.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-job.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "fd-util.h"
#include "log.h"
#include "missing.h"
#include "mkdir.h"
#include "sd-bus.h"
#include "selinux-access.h"
#include "special.h"
#include "strv.h"
#include "strxcpyx.h"


#define CONNECTIONS_MAX 4096

static void destroy_bus(Manager *m, sd_bus **bus);

// int
// bus_send_queued_message(Manager *m)
// {
// 	int r;

// 	assert(m);

// 	if (!m->queued_message)
// 		return 0;

// 	assert(m->queued_message_bus);

// 	/* If we cannot get rid of this message we won't dispatch any
//          * D-Bus messages, so that we won't end up wanting to queue
//          * another message. */

// 	r = sd_bus_send(m->queued_message_bus, m->queued_message, NULL);
// 	if (r < 0)
// 		log_warning_errno(r, "Failed to send queued message: %m");

// 	m->queued_message = sd_bus_message_unref(m->queued_message);
// 	m->queued_message_bus = sd_bus_unref(m->queued_message_bus);

// 	return 0;
// }

int
bus_forward_agent_released(Manager *m, const char *path)
{
	int r;

	assert(m);
	assert(path);

	if (m->running_as != SYSTEMD_SYSTEM)
		return 0;

	if (!m->system_bus)
		return 0;

	/* If we are running a system instance we forward the agent message on the system bus, so that the user
         * instances get notified about this, too */

	r = sd_bus_emit_signal(m->system_bus, "/org/freedesktop/systemd1/agent",
		SVC_DBUS_INTERFACE ".Agent", "Released", "s", path);
	if (r < 0)
		return log_debug_errno(r,
			"Failed to propagate agent release message: %m");

	return 1;
}

static int signal_agent_released(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *cgroup;
        uid_t sender_uid;
        int r;

        assert(message);

        /* only accept org.freedesktop.systemd1.Agent from UID=0 */
        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0 || sender_uid != 0)
                return 0;

        /* parse 'cgroup-empty' notification */
        r = sd_bus_message_read(message, "s", &cgroup);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        manager_notify_cgroup_empty(m, cgroup);
        return 0;
}

static int signal_disconnected(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        sd_bus *bus;

        assert(message);
        assert_se(bus = sd_bus_message_get_bus(message));

        if (bus == m->api_bus)
                bus_done_api(m);
        if (bus == m->system_bus)
                bus_done_system(m);

        if (set_remove(m->private_buses, bus)) {
                log_debug("Got disconnect on private connection.");
                destroy_bus(m, &bus);
        }

        return 0;
}

// static int
// signal_name_owner_changed(sd_bus *bus, sd_bus_message *message, void *userdata,
// 	sd_bus_error *error)
// {
// 	const char *name, *old_owner, *new_owner;
// 	Manager *m = userdata;
// 	int r;

// 	assert(bus);
// 	assert(message);
// 	assert(m);

// 	r = sd_bus_message_read(message, "sss", &name, &old_owner, &new_owner);
// 	if (r < 0) {
// 		bus_log_parse_error(r);
// 		return 0;
// 	}

// 	manager_dispatch_bus_name_owner_changed(m, name,
// 		isempty(old_owner) ? NULL : old_owner,
// 		isempty(new_owner) ? NULL : new_owner);

// 	return 0;
// }

static int signal_activation_request(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SOCKET) ||
            manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SERVICE)) {
                r = sd_bus_error_set(&error, BUS_ERROR_SHUTTING_DOWN, "Refusing activation, D-Bus is shutting down.");
                goto failed;
        }

        r = manager_load_unit(m, name, NULL, &error, &u);
        if (r < 0)
                goto failed;

        if (u->refuse_manual_start) {
                r = sd_bus_error_setf(&error, BUS_ERROR_ONLY_BY_DEPENDENCY, "Operation refused, %s may be requested by dependency only (it is configured to refuse manual start/stop).", u->id);
                goto failed;
        }

        r = manager_add_job(m, JOB_START, u, JOB_REPLACE, NULL, &error, NULL);
        if (r < 0)
                goto failed;

        /* Successfully queued, that's it for us */
        return 0;

failed:
        if (!sd_bus_error_is_set(&error))
                sd_bus_error_set_errno(&error, r);

        log_debug("D-Bus activation failed for %s: %s", name, bus_error_message(&error, r));

        r = sd_bus_message_new_signal(sd_bus_message_get_bus(message), &reply, "/org/freedesktop/systemd1", SVC_DBUS_INTERFACE ".Activator", "ActivationFailure");
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_message_append(reply, "sss", name, error.name, error.message);
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_send_to(NULL, reply, "org.freedesktop.DBus", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to respond with to bus activation request: %m");

        return 0;
}

#ifdef HAVE_SELINUX
static int
mac_selinux_filter(sd_bus *bus, sd_bus_message *message, void *userdata,
	sd_bus_error *error)
{
	Manager *m = userdata;
	const char *verb, *path;
	Unit *u = NULL;
	Job *j;
	int r;

	assert(bus);
	assert(message);

	/* Our own method calls are all protected individually with
         * selinux checks, but the built-in interfaces need to be
         * protected too. */

	if (sd_bus_message_is_method_call(message,
		    "org.freedesktop.DBus.Properties", "Set"))
		verb = "reload";
	else if (sd_bus_message_is_method_call(message,
			 "org.freedesktop.DBus.Introspectable", NULL) ||
		sd_bus_message_is_method_call(message,
			"org.freedesktop.DBus.Properties", NULL) ||
		sd_bus_message_is_method_call(message,
			"org.freedesktop.DBus.ObjectManager", NULL) ||
		sd_bus_message_is_method_call(message,
			"org.freedesktop.DBus.Peer", NULL))
		verb = "status";
	else
		return 0;

	path = sd_bus_message_get_path(message);

	if (object_path_startswith("/org/freedesktop/systemd1", path)) {
		r = mac_selinux_access_check(message, verb, error);
		if (r < 0)
			return r;

		return 0;
	}

	if (streq_ptr(path, "/org/freedesktop/systemd1/unit/self")) {
		_cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
		pid_t pid;

		r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID,
			&creds);
		if (r < 0)
			return 0;

		r = sd_bus_creds_get_pid(creds, &pid);
		if (r < 0)
			return 0;

		u = manager_get_unit_by_pid(m, pid);
	} else {
		r = manager_get_job_from_dbus_path(m, path, &j);
		if (r >= 0)
			u = j->unit;
		else
			manager_load_unit_from_dbus_path(m, path, NULL, &u);
	}

	if (!u)
		return 0;

	r = mac_selinux_unit_access_check(u, message, verb, error);
	if (r < 0)
		return r;

	return 0;
}
#endif

static int
bus_job_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	Job *j;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = manager_get_job_from_dbus_path(m, path, &j);
	if (r < 0)
		return 0;

	*found = j;
	return 1;
}

static int find_unit(Manager *m, sd_bus *bus, const char *path, Unit **unit, sd_bus_error *error) {
        Unit *u = NULL;  /* just to appease gcc, initialization is not really necessary */
        int r;

        assert(m);
        assert(bus);
        assert(path);

        if (streq(path, "/org/freedesktop/systemd1/unit/self")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                sd_bus_message *message;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pidref(m, &pidref);
                if (!u)
                        return 0;
        } else {
                r = manager_load_unit_from_dbus_path(m, path, error, &u);
                if (r < 0)
                        return 0;
                assert(u);
        }

        *unit = u;
        return 1;
}

static int
bus_unit_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	return find_unit(m, bus, path, (Unit **)found, error);
}

static int
bus_unit_interface_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	Unit *u;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = find_unit(m, bus, path, &u, error);
	if (r <= 0)
		return r;

	if (!streq_ptr(interface, UNIT_VTABLE(u)->bus_interface))
		return 0;

	*found = u;
	return 1;
}

static int
bus_unit_cgroup_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	Unit *u;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = find_unit(m, bus, path, &u, error);
	if (r <= 0)
		return r;

	if (!streq_ptr(interface, UNIT_VTABLE(u)->bus_interface))
		return 0;

	if (!unit_get_cgroup_context(u))
		return 0;

	*found = u;
	return 1;
}

static int
bus_cgroup_context_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	CGroupContext *c;
	Unit *u;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = find_unit(m, bus, path, &u, error);
	if (r <= 0)
		return r;

	if (!streq_ptr(interface, UNIT_VTABLE(u)->bus_interface))
		return 0;

	c = unit_get_cgroup_context(u);
	if (!c)
		return 0;

	*found = c;
	return 1;
}

static int
bus_exec_context_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	ExecContext *c;
	Unit *u;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = find_unit(m, bus, path, &u, error);
	if (r <= 0)
		return r;

	if (!streq_ptr(interface, UNIT_VTABLE(u)->bus_interface))
		return 0;

	c = unit_get_exec_context(u);
	if (!c)
		return 0;

	*found = c;
	return 1;
}

static int
bus_kill_context_find(sd_bus *bus, const char *path, const char *interface,
	void *userdata, void **found, sd_bus_error *error)
{
	Manager *m = userdata;
	KillContext *c;
	Unit *u;
	int r;

	assert(bus);
	assert(path);
	assert(interface);
	assert(found);
	assert(m);

	r = find_unit(m, bus, path, &u, error);
	if (r <= 0)
		return r;

	if (!streq_ptr(interface, UNIT_VTABLE(u)->bus_interface))
		return 0;

	c = unit_get_kill_context(u);
	if (!c)
		return 0;

	*found = c;
	return 1;
}

static int
bus_job_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes,
	sd_bus_error *error)
{
	_cleanup_free_ char **l = NULL;
	Manager *m = userdata;
	unsigned k = 0;
	Iterator i;
	Job *j;

	l = new0(char *, hashmap_size(m->jobs) + 1);
	if (!l)
		return -ENOMEM;

	HASHMAP_FOREACH (j, m->jobs) {
		l[k] = job_dbus_path(j);
		if (!l[k])
			return -ENOMEM;

		k++;
	}

	assert(hashmap_size(m->jobs) == k);

	*nodes = l;
	l = NULL;

	return k;
}

static int
bus_unit_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes,
	sd_bus_error *error)
{
	_cleanup_free_ char **l = NULL;
	Manager *m = userdata;
	unsigned k = 0;
	Iterator i;
	Unit *u;

	l = new0(char *, hashmap_size(m->units) + 1);
	if (!l)
		return -ENOMEM;

	HASHMAP_FOREACH (u, m->units) {
		l[k] = unit_dbus_path(u);
		if (!l[k])
			return -ENOMEM;

		k++;
	}

	*nodes = l;
	l = NULL;

	return k;
}

static int
bus_setup_api_vtables(Manager *m, sd_bus *bus)
{
	UnitType t;
	int r;

	assert(m);
	assert(bus);

#ifdef HAVE_SELINUX
	r = sd_bus_add_filter(bus, NULL, mac_selinux_filter, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to add SELinux access filter: %m");
#endif

	r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/systemd1",
		SVC_DBUS_INTERFACE ".Manager", bus_manager_vtable, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to register Manager vtable: %m");

	r = sd_bus_add_fallback_vtable(bus, NULL,
		"/org/freedesktop/systemd1/job", SVC_DBUS_INTERFACE ".Job",
		bus_job_vtable, bus_job_find, m);
	if (r < 0)
		return log_error_errno(r, "Failed to register Job vtable: %m");

	r = sd_bus_add_node_enumerator(bus, NULL,
		"/org/freedesktop/systemd1/job", bus_job_enumerate, m);
	if (r < 0)
		return log_error_errno(r, "Failed to add job enumerator: %m");

	r = sd_bus_add_fallback_vtable(bus, NULL,
		"/org/freedesktop/systemd1/unit", SVC_DBUS_INTERFACE ".Unit",
		bus_unit_vtable, bus_unit_find, m);
	if (r < 0)
		return log_error_errno(r, "Failed to register Unit vtable: %m");

	r = sd_bus_add_node_enumerator(bus, NULL,
		"/org/freedesktop/systemd1/unit", bus_unit_enumerate, m);
	if (r < 0)
		return log_error_errno(r, "Failed to add job enumerator: %m");

	for (t = 0; t < _UNIT_TYPE_MAX; t++) {
		r = sd_bus_add_fallback_vtable(bus, NULL,
			"/org/freedesktop/systemd1/unit",
			unit_vtable[t]->bus_interface,
			unit_vtable[t]->bus_vtable, bus_unit_interface_find, m);
		if (r < 0)
			return log_error_errno(r,
				"Failed to register type specific vtable for %s: %m",
				unit_vtable[t]->bus_interface);

		if (unit_vtable[t]->cgroup_context_offset > 0) {
			r = sd_bus_add_fallback_vtable(bus, NULL,
				"/org/freedesktop/systemd1/unit",
				unit_vtable[t]->bus_interface,
				bus_unit_cgroup_vtable, bus_unit_cgroup_find,
				m);
			if (r < 0)
				return log_error_errno(r,
					"Failed to register control group unit vtable for %s: %m",
					unit_vtable[t]->bus_interface);

			r = sd_bus_add_fallback_vtable(bus, NULL,
				"/org/freedesktop/systemd1/unit",
				unit_vtable[t]->bus_interface,
				bus_cgroup_vtable, bus_cgroup_context_find, m);
			if (r < 0)
				return log_error_errno(r,
					"Failed to register control group vtable for %s: %m",
					unit_vtable[t]->bus_interface);
		}

		if (unit_vtable[t]->exec_context_offset > 0) {
			r = sd_bus_add_fallback_vtable(bus, NULL,
				"/org/freedesktop/systemd1/unit",
				unit_vtable[t]->bus_interface, bus_exec_vtable,
				bus_exec_context_find, m);
			if (r < 0)
				return log_error_errno(r,
					"Failed to register execute vtable for %s: %m",
					unit_vtable[t]->bus_interface);
		}

		if (unit_vtable[t]->kill_context_offset > 0) {
			r = sd_bus_add_fallback_vtable(bus, NULL,
				"/org/freedesktop/systemd1/unit",
				unit_vtable[t]->bus_interface, bus_kill_vtable,
				bus_kill_context_find, m);
			if (r < 0)
				return log_error_errno(r,
					"Failed to register kill vtable for %s: %m",
					unit_vtable[t]->bus_interface);
		}
	}

	return 0;
}

static int
bus_setup_disconnected_match(Manager *m, sd_bus *bus)
{
	int r;

	assert(m);
	assert(bus);

	r = sd_bus_add_match(bus, NULL,
		"sender='org.freedesktop.DBus.Local',"
		"type='signal',"
		"path='/org/freedesktop/DBus/Local',"
		"interface='org.freedesktop.DBus.Local',"
		"member='Disconnected'",
		signal_disconnected, m);

	if (r < 0)
		return log_error_errno(r,
			"Failed to register match for Disconnected message: %m");

	return 0;
}

static int bus_on_connection(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int nfd = -EBADF;
        Manager *m = ASSERT_PTR(userdata);
        sd_id128_t id;
        int r;

        assert(s);

        nfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (nfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                log_warning_errno(errno, "Failed to accept private connection, ignoring: %m");
                return 0;
        }

        if (set_size(m->private_buses) >= CONNECTIONS_MAX) {
                log_warning("Too many concurrent connections, refusing");
                return 0;
        }

        r = sd_bus_new(&bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to allocate new private connection bus: %m");
                return 0;
        }

        (void) sd_bus_set_description(bus, "private-bus-connection");

        r = sd_bus_set_fd(bus, nfd, nfd);
        if (r < 0) {
                log_warning_errno(r, "Failed to set fd on new connection bus: %m");
                return 0;
        }

        TAKE_FD(nfd);

        r = bus_check_peercred(bus);
        if (r < 0) {
                log_warning_errno(r, "Incoming private connection from unprivileged client, refusing: %m");
                return 0;
        }

        assert_se(sd_id128_randomize(&id) >= 0);

        r = sd_bus_set_server(bus, 1, id);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable server support for new connection bus: %m");
                return 0;
        }

        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT|
                                   SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable credentials for new connection: %m");
                return 0;
        }

        r = sd_bus_set_sender(bus, "org.freedesktop.systemd1");
        if (r < 0) {
                log_warning_errno(r, "Failed to set direct connection sender: %m");
                return 0;
        }

        r = sd_bus_start(bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to start new connection bus: %m");
                return 0;
        }

// HACK!
#if 0
        if (DEBUG_LOGGING) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
                const char *comm = NULL, *description = NULL;
                pid_t pid = 0;

                r = sd_bus_get_owner_creds(bus, SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION, &c);
                if (r < 0)
                        log_warning_errno(r, "Failed to get peer creds, ignoring: %m");
                else {
                        (void) sd_bus_creds_get_pid(c, &pid);
                        (void) sd_bus_creds_get_comm(c, &comm);
                        (void) sd_bus_creds_get_description(c, &description);
                }

                log_debug("Accepting direct incoming connection from " PID_FMT " (%s) [%s]", pid, strna(comm), strna(description));
        }
#endif

        r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
        if (r < 0) {
                log_warning_errno(r, "Failed to attach new connection bus to event loop: %m");
                return 0;
        }

        r = bus_setup_disconnected_match(m, bus);
        if (r < 0)
                return 0;

        r = bus_setup_api_vtables(m, bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to set up API vtables on new connection bus: %m");
                return 0;
        }

        r = bus_register_malloc_status(bus, "org.freedesktop.systemd1");
        if (r < 0)
                log_warning_errno(r, "Failed to register MemoryAllocation1, ignoring: %m");

        r = set_ensure_put(&m->private_buses, NULL, bus);
        if (r == -ENOMEM) {
                log_oom();
                return 0;
        }
        if (r < 0) {
                log_warning_errno(r, "Failed to add new connection bus to set: %m");
                return 0;
        }

        TAKE_PTR(bus);

        log_debug("Accepted new private connection.");

        return 0;
}

static int
bus_list_names(Manager *m, sd_bus *bus)
{
	_cleanup_strv_free_ char **names = NULL;
	char **i;
	int r;

	assert(m);
	assert(bus);

	r = sd_bus_list_names(bus, &names, NULL);
	if (r < 0)
		return log_error_errno(r,
			"Failed to get initial list of names: %m");

	/* This is a bit hacky, we say the owner of the name is the
         * name itself, because we don't want the extra traffic to
         * figure out the real owner. */
	STRV_FOREACH (i, names)
		manager_dispatch_bus_name_owner_changed(m, *i, NULL, *i);

	return 0;
}

static int bus_setup_api(Manager *m, sd_bus *bus) {
        char *name;
        Unit *u;
        int r;

        assert(m);
        assert(bus);

        /* Let's make sure we have enough credential bits so that we can make security and selinux decisions */
        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0)
                log_warning_errno(r, "Failed to enable credential passing, ignoring: %m");

        r = bus_setup_api_vtables(m, bus);
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, name, m->watch_bus) {
                r = unit_install_bus_match(u, bus, name);
                if (r < 0)
                        log_error_errno(r, "Failed to subscribe to NameOwnerChanged signal for '%s': %m", name);
        }

        r = sd_bus_match_signal_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        SVC_DBUS_BUSNAME ".Activator",
                        "ActivationRequest",
                        signal_activation_request, NULL, m);
        if (r < 0)
                log_warning_errno(r, "Failed to subscribe to activation signal: %m");

        /* Allow replacing of our name, to ease implementation of reexecution, where we keep the old connection open
         * until after the new connection is set up and the name installed to allow clients to synchronously wait for
         * reexecution to finish */
        r = sd_bus_request_name_async(bus, NULL, SVC_DBUS_BUSNAME, SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_ALLOW_REPLACEMENT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = bus_register_malloc_status(bus, SVC_DBUS_BUSNAME);
        if (r < 0)
                log_warning_errno(r, "Failed to register MemoryAllocation1, ignoring: %m");

        log_debug("Successfully connected to API bus.");

        return 0;
}

int bus_init_api(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (m->api_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->system_bus)
                bus = sd_bus_ref(m->system_bus);
        else {
                if (MANAGER_IS_SYSTEM(m))
                        r = sd_bus_open_system_with_description(&bus, "bus-api-system");
                else
                        r = sd_bus_open_user_with_description(&bus, "bus-api-user");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to API bus: %m");

                r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach API bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        r = bus_setup_api(m, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to set up API bus: %m");

        m->api_bus = TAKE_PTR(bus);

        return 0;
}

static int
bus_setup_system(Manager *m, sd_bus *bus)
{
	int r;

	assert(m);
	assert(bus);

	if (m->running_as == SYSTEMD_SYSTEM)
		return 0;

	/* If we are a user instance we get the Released message via
         * the system bus */
	r = sd_bus_add_match(bus, NULL,
		"type='signal',"
		"interface='" SVC_DBUS_INTERFACE ".Agent',"
		"member='Released',"
		"path='/org/freedesktop/systemd1/agent'",
		signal_agent_released, m);

	if (r < 0)
		log_warning_errno(r,
			"Failed to register Released match on system bus: %m");

	log_debug("Successfully connected to system bus.");
	return 0;
}

int bus_init_system(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (m->system_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->api_bus)
                bus = sd_bus_ref(m->api_bus);
        else {
                r = sd_bus_open_system_with_description(&bus, "bus-system");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to system bus: %m");

                r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach system bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        r = bus_setup_system(m, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to set up system bus: %m");

        m->system_bus = TAKE_PTR(bus);

        return 0;
}

static int
bus_init_private(Manager *m)
{
	_cleanup_close_ int fd = -1;
	union sockaddr_union sa = { .un.sun_family = AF_UNIX };
	sd_event_source *s;
	socklen_t salen;
	int r;

	assert(m);

	if (m->private_listen_fd >= 0)
		return 0;

	if (m->running_as == SYSTEMD_SYSTEM) {
#if 0 /* actually we don't care */
		/* We want the private bus only when running as init */
		if (getpid() != 1)
			return 0;
#endif

		strcpy(sa.un.sun_path, SVC_PKGRUNSTATEDIR "/private");
		salen = offsetof(union sockaddr_union, un.sun_path) +
			strlen(SVC_PKGRUNSTATEDIR "/private");
	} else {
		size_t left = sizeof(sa.un.sun_path);
		char *p = sa.un.sun_path;
		const char *e;

		e = secure_getenv("XDG_RUNTIME_DIR");
		if (!e) {
			log_error("Failed to determine XDG_RUNTIME_DIR");
			return -EHOSTDOWN;
		}

		left = strpcpy(&p, left, e);
		left = strpcpy(&p, left, "/" SVC_PKGDIRNAME "/private");

		salen = sizeof(sa.un) - left;
	}

	(void)mkdir_parents_label(sa.un.sun_path, 0755);
	(void)unlink(sa.un.sun_path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return log_error_errno(errno,
			"Failed to allocate private socket: %m");

	r = bind(fd, &sa.sa, salen);
	if (r < 0)
		return log_error_errno(errno,
			"Failed to bind private socket: %m");

	r = listen(fd, SOMAXCONN);
	if (r < 0)
		return log_error_errno(errno,
			"Failed to make private socket listening: %m");

	r = sd_event_add_io(m->event, &s, fd, EPOLLIN, bus_on_connection, m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to allocate event source: %m");

	m->private_listen_fd = fd;
	m->private_listen_event_source = s;
	fd = -1;

	log_debug("Successfully created private D-Bus server.");

	return 0;
}

int
bus_init(Manager *m, bool try_bus_connect)
{
	int r;

	if (try_bus_connect) {
		r = bus_init_system(m);
		if (r < 0)
			return log_error_errno(r,
				"Failed to initialize D-Bus connection: %m");

		r = bus_init_api(m);
		if (r < 0)
			return log_error_errno(r,
				"Error occured during D-Bus APIs initialization: %m");
	}

	r = bus_init_private(m);
	if (r < 0)
		return log_error_errno(r,
			"Failed to create private D-Bus server: %m");

	return 0;
}

static void destroy_bus(Manager *m, sd_bus **bus) {
        Unit *u;
        Job *j;

        assert(m);
        assert(bus);

        if (!*bus)
                return;

        /* Make sure all bus slots watching names are released. */
        HASHMAP_FOREACH(u, m->watch_bus) {
                if (u->match_bus_slot && sd_bus_slot_get_bus(u->match_bus_slot) == *bus)
                        u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
                if (u->get_name_owner_slot && sd_bus_slot_get_bus(u->get_name_owner_slot) == *bus)
                        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);
        }

        /* Get rid of tracked clients on this bus */
        if (m->subscribed && sd_bus_track_get_bus(m->subscribed) == *bus)
                m->subscribed = sd_bus_track_unref(m->subscribed);

        HASHMAP_FOREACH(j, m->jobs)
                if (j->bus_track && sd_bus_track_get_bus(j->bus_track) == *bus)
                        j->bus_track = sd_bus_track_unref(j->bus_track);

        HASHMAP_FOREACH(u, m->units) {
                if (u->bus_track && sd_bus_track_get_bus(u->bus_track) == *bus)
                        u->bus_track = sd_bus_track_unref(u->bus_track);

                // HACK!
                // /* Get rid of pending freezer messages on this bus */
                // if (u->pending_freezer_invocation && sd_bus_message_get_bus(u->pending_freezer_invocation) == *bus)
                //         u->pending_freezer_invocation = sd_bus_message_unref(u->pending_freezer_invocation);
        }

        /* Get rid of queued message on this bus */
        if (m->pending_reload_message && sd_bus_message_get_bus(m->pending_reload_message) == *bus)
                m->pending_reload_message = sd_bus_message_unref(m->pending_reload_message);

        /* Possibly flush unwritten data, but only if we are
         * unprivileged, since we don't want to sync here */
        if (!MANAGER_IS_SYSTEM(m))
                sd_bus_flush(*bus);

        /* And destroy the object */
        *bus = sd_bus_close_unref(*bus);
}

void
bus_done(Manager *m)
{
	sd_bus *b;

	assert(m);

	if (m->api_bus)
		destroy_bus(m, &m->api_bus);
	if (m->system_bus)
		destroy_bus(m, &m->system_bus);
	while ((b = set_steal_first(m->private_buses)))
		destroy_bus(m, &b);

	set_free(m->private_buses);
	m->private_buses = NULL;

	m->subscribed = sd_bus_track_unref(m->subscribed);
	strv_free(m->deserialized_subscribed);
	m->deserialized_subscribed = NULL;

	if (m->private_listen_event_source)
		m->private_listen_event_source =
			sd_event_source_unref(m->private_listen_event_source);

	m->private_listen_fd = safe_close(m->private_listen_fd);

	bus_verify_polkit_async_registry_free(m->polkit_registry);
}

int
bus_fdset_add_all(Manager *m, FDSet *fds)
{
	Iterator i;
	sd_bus *b;
	int fd;

	assert(m);
	assert(fds);

	/* When we are about to reexecute we add all D-Bus fds to the
         * set to pass over to the newly executed systemd. They won't
         * be used there however, except thatt they are closed at the
         * very end of deserialization, those making it possible for
         * clients to synchronously wait for systemd to reexec by
         * simply waiting for disconnection */

	if (m->api_bus) {
		fd = sd_bus_get_fd(m->api_bus);
		if (fd >= 0) {
			fd = fdset_put_dup(fds, fd);
			if (fd < 0)
				return fd;
		}
	}

	SET_FOREACH (b, m->private_buses) {
		fd = sd_bus_get_fd(b);
		if (fd >= 0) {
			fd = fdset_put_dup(fds, fd);
			if (fd < 0)
				return fd;
		}
	}

	/* We don't offer any APIs on the system bus (well, unless it
         * is the same as the API bus) hence we don't bother with it
         * here */

	return 0;
}

int
bus_foreach_bus(Manager *m, sd_bus_track *subscribed2,
	int (*send_message)(sd_bus *bus, void *userdata), void *userdata)
{
	Iterator i;
	sd_bus *b;
	int r, ret = 0;

	/* Send to all direct busses, unconditionally */
	SET_FOREACH (b, m->private_buses) {
		r = send_message(b, userdata);
		if (r < 0)
			ret = r;
	}

	/* Send to API bus, but only if somebody is subscribed */
	if (sd_bus_track_count(m->subscribed) > 0 ||
		sd_bus_track_count(subscribed2) > 0) {
		r = send_message(m->api_bus, userdata);
		if (r < 0)
			ret = r;
	}

	return ret;
}

void
bus_track_serialize(sd_bus_track *t, FILE *f)
{
	const char *n;

	assert(f);

	for (n = sd_bus_track_first(t); n; n = sd_bus_track_next(t))
		fprintf(f, "subscribed=%s\n", n);
}

int
bus_track_deserialize_item(char ***l, const char *line)
{
	const char *e;
	int r;

	assert(l);
	assert(line);

	e = startswith(line, "subscribed=");
	if (!e)
		return 0;

	r = strv_extend(l, e);
	if (r < 0)
		return r;

	return 1;
}

int
bus_track_coldplug(Manager *m, sd_bus_track **t, char ***l)
{
	int r = 0;

	assert(m);
	assert(t);
	assert(l);

	if (!strv_isempty(*l) && m->api_bus) {
		char **i;

		if (!*t) {
			r = sd_bus_track_new(m->api_bus, t, NULL, NULL);
			if (r < 0)
				return r;
		}

		r = 0;
		STRV_FOREACH (i, *l) {
			int k;

			k = sd_bus_track_add_name(*t, *i);
			if (k < 0)
				r = k;
		}
	}

	strv_free(*l);
	*l = NULL;

	return r;
}

int bus_verify_manage_unit_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(
                        call,
                        SVC_DBUS_INTERFACE ".manage-units",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
}

/* Same as bus_verify_manage_unit_async(), but checks for CAP_KILL instead of CAP_SYS_ADMIN */
// int
// bus_verify_manage_unit_async_for_kill(Manager *m, sd_bus_message *call,
// 	sd_bus_error *error)
// {
// 	return bus_verify_polkit_async(call, CAP_KILL,
// 		SVC_DBUS_INTERFACE ".manage-units", false, &m->polkit_registry,
// 		error);
// }

int bus_verify_manage_unit_files_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(
                        call,
                        SVC_DBUS_INTERFACE ".manage-unit-files",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
}

int bus_verify_reload_daemon_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(
                        call,
                        SVC_DBUS_INTERFACE ".reload-daemon",
                        /* details= */ NULL,
                        &m->polkit_registry, error);
}

int bus_verify_manage_units_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(
                        call,
                        SVC_DBUS_INTERFACE ".manage-units",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
}
