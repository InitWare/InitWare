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
#include <sys/statvfs.h>

#include "alloc-util.h"
#include "architecture.h"
#include "bsdcapability.h"
#include "build.h"
#include "bus-common-errors.h"
#include "chase.h"
#include "clock-util.h"
#include "data-fd-util.h"
#include "dbus-execute.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-snapshot.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "install.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "selinux-access.h"
#include "strv.h"
#include "virt.h"
#include "watchdog.h"

/* Require 16MiB free in /run/systemd for reloading/reexecing. After all we need to serialize our state
 * there, and if we can't we'll fail badly. */
#define RELOAD_DISK_SPACE_MIN (UINT64_C(16) * UINT64_C(1024) * UINT64_C(1024))

static UnitFileFlags
unit_file_bools_to_flags(bool runtime, bool force)
{
	return (runtime ? UNIT_FILE_RUNTIME : 0) |
		(force ? UNIT_FILE_FORCE : 0);
}

static int
property_get_version(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	assert(bus);
	assert(reply);

	return sd_bus_message_append(reply, "s", PACKAGE_VERSION);
}

static int
property_get_features(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	assert(bus);
	assert(reply);

	return sd_bus_message_append(reply, "s", SYSTEMD_FEATURES);
}

static int property_get_virtualization(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Virtualization v;

        assert(bus);
        assert(reply);

        v = detect_virtualization();

        /* Make sure to return the empty string when we detect no virtualization, as that is the API.
         *
         * https://github.com/systemd/systemd/issues/1423
         */

        return sd_bus_message_append(
                        reply, "s",
                        v == VIRTUALIZATION_NONE ? NULL : virtualization_to_string(v));
}

static int
property_get_architecture(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	assert(bus);
	assert(reply);

	return sd_bus_message_append(reply, "s",
		architecture_to_string(uname_architecture()));
}

static int
property_get_tainted(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	char buf[sizeof(
		"split-usr:mtab-not-symlink:cgroups-missing:local-hwclock:")] =
		"",
     *e = buf;
	_cleanup_free_ char *p = NULL;
	Manager *m = userdata;

	assert(bus);
	assert(reply);
	assert(m);

	if (m->taint_usr)
		e = stpcpy(e, "split-usr:");

	if (readlink_malloc("/etc/mtab", &p) < 0)
		e = stpcpy(e, "mtab-not-symlink:");

	if (access("/proc/cgroups", F_OK) < 0)
		e = stpcpy(e, "cgroups-missing:");

#ifdef SVC_PLATFORM_Linux
	if (clock_is_localtime() > 0)
		e = stpcpy(e, "local-hwclock:");
#endif

	/* remove the last ':' */
	if (e != buf)
		e[-1] = 0;

	return sd_bus_message_append(reply, "s", buf);
}

static int
property_get_log_target(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	assert(bus);
	assert(reply);

	return sd_bus_message_append(reply, "s",
		log_target_to_string(log_get_target()));
}

static int
property_set_log_target(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *value, void *userdata,
	sd_bus_error *error)
{
	const char *t;
	int r;

	assert(bus);
	assert(value);

	r = sd_bus_message_read(value, "s", &t);
	if (r < 0)
		return r;

	return log_set_target_from_string(t);
}

static int
property_get_log_level(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	_cleanup_free_ char *t = NULL;
	int r;

	assert(bus);
	assert(reply);

	r = log_level_to_string_alloc(log_get_max_level(), &t);
	if (r < 0)
		return r;

	return sd_bus_message_append(reply, "s", t);
}

static int
property_set_log_level(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *value, void *userdata,
	sd_bus_error *error)
{
	const char *t;
	int r;

	assert(bus);
	assert(value);

	r = sd_bus_message_read(value, "s", &t);
	if (r < 0)
		return r;

	return log_set_max_level_from_string(t);
}

static int
property_get_n_names(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Manager *m = userdata;

	assert(bus);
	assert(reply);
	assert(m);

	return sd_bus_message_append(reply, "u",
		(uint32_t)hashmap_size(m->units));
}

static int
property_get_n_failed_units(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error)
{
	Manager *m = userdata;

	assert(bus);
	assert(reply);
	assert(m);

	return sd_bus_message_append(reply, "u",
		(uint32_t)set_size(m->failed_units));
}

static int
property_get_n_jobs(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Manager *m = userdata;

	assert(bus);
	assert(reply);
	assert(m);

	return sd_bus_message_append(reply, "u",
		(uint32_t)hashmap_size(m->jobs));
}

static int
property_get_progress(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Manager *m = userdata;
	double d;

	assert(bus);
	assert(reply);
	assert(m);

	if (dual_timestamp_is_set(&m->finish_timestamp))
		d = 1.0;
	else
		d = 1.0 -
			((double)hashmap_size(m->jobs) /
				(double)m->n_installed_jobs);

	return sd_bus_message_append(reply, "d", d);
}

static int
property_get_system_state(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Manager *m = userdata;

	assert(bus);
	assert(reply);
	assert(m);

	return sd_bus_message_append(reply, "s",
		manager_state_to_string(manager_state(m)));
}

static int
property_set_runtime_watchdog(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *value,
	void *userdata, sd_bus_error *error)
{
	usec_t *t = userdata;
	int r;

	assert(bus);
	assert(value);

	assert_cc(sizeof(usec_t) == sizeof(uint64_t));

	r = sd_bus_message_read(value, "t", t);
	if (r < 0)
		return r;

	return watchdog_set_timeout(t);
}

static int bus_get_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *error) {
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(ret_unit);

        /* More or less a wrapper around manager_get_unit() that generates nice errors and has one trick up
         * its sleeve: if the name is specified empty we use the client's unit. */

        if (isempty(name)) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pidref(m, &pidref);
                if (!u)
                        return sd_bus_error_set(error, BUS_ERROR_NO_SUCH_UNIT, "Client not member of any unit.");
        } else {
                u = manager_get_unit(m, name);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", name);
        }

        *ret_unit = u;
        return 0;
}

static int bus_load_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *error) {
        assert(m);
        assert(message);
        assert(ret_unit);

        /* Pretty much the same as bus_get_unit_by_name(), but we also load the unit if necessary. */

        if (isempty(name))
                return bus_get_unit_by_name(m, message, name, ret_unit, error);

        return manager_load_unit(m, name, NULL, error, ret_unit);
}

static int reply_unit_path(Unit *u, sd_bus_message *message, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(u);
        assert(message);

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return log_oom();

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, error);
}

static int method_get_unit_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Unit *u;
        int r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &pidref.pid);
        if (r < 0)
                return r;
        if (pidref.pid < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid PID " PID_FMT, pidref.pid);
        if (pidref.pid == 0) {
                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;
        }

        u = manager_get_unit_by_pidref(m, &pidref);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_UNIT_FOR_PID, "PID "PID_FMT" does not belong to any loaded unit.", pidref.pid);

        return reply_unit_path(u, message, error);
}

static int method_load_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_load_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, error);
}

static int method_start_unit_generic(sd_bus_message *message, Manager *m, JobType job_type, bool reload_if_possible, sd_bus_error *error) {
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        return bus_unit_method_start_generic(message, u, job_type, reload_if_possible, error);
}

static int method_start_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_START, /* reload_if_possible = */ false, error);
}

static int method_stop_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_STOP, /* reload_if_possible = */ false, error);
}

static int method_reload_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RELOAD, /* reload_if_possible = */ false, error);
}

static int method_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, /* reload_if_possible = */ false, error);
}

static int method_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, /* reload_if_possible = */ false, error);
}

static int method_reload_or_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, /* reload_if_possible = */ true, error);
}

static int method_reload_or_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, /* reload_if_possible = */ true, error);
}

typedef enum GenericUnitOperationFlags {
        GENERIC_UNIT_LOAD            = 1 << 0, /* Load if the unit is not loaded yet */
        GENERIC_UNIT_VALIDATE_LOADED = 1 << 1, /* Verify unit is properly loaded before forwarding call */
} GenericUnitOperationFlags;

static int method_generic_unit_operation(
                sd_bus_message *message,
                Manager *m,
                sd_bus_error *error,
                sd_bus_message_handler_t handler,
                GenericUnitOperationFlags flags) {

        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);
        assert(handler);

        /* Read the first argument from the command and pass the operation to the specified per-unit
         * method. */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!isempty(name) && FLAGS_SET(flags, GENERIC_UNIT_LOAD))
                r = manager_load_unit(m, name, NULL, error, &u);
        else
                r = bus_get_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, GENERIC_UNIT_VALIDATE_LOADED)) {
                r = bus_unit_validate_load_state(u, error);
                if (r < 0)
                        return r;
        }

        return handler(message, u, error);
}

static int method_start_unit_replace(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *old_name;
        Unit *u;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, old_name, &u, error);
        if (r < 0)
                return r;
        if (!u->job || u->job->type != JOB_START)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "No job queued for unit %s", old_name);

        return method_start_unit_generic(message, m, JOB_START, /* reload_if_possible = */ false, error);
}

static int method_kill_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* We don't bother with GENERIC_UNIT_LOAD nor GENERIC_UNIT_VALIDATE_LOADED here, as it shouldn't
         * matter whether a unit is loaded for killing any processes possibly in the unit's cgroup. */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_kill, 0);
}

static int method_reset_failed_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Don't load the unit (because unloaded units can't be in failed state), and don't insist on the
         * unit to be loaded properly (since a failed unit might have its unit file disappeared) */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_reset_failed, 0);
}

static int method_set_unit_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Only change properties on fully loaded units, and load them in order to set properties */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_set_properties, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int reply_unit_info(sd_bus_message *reply, Unit *u) {
        _cleanup_free_ char *unit_path = NULL, *job_path = NULL;
        Unit *following;

        following = unit_following(u);

        unit_path = unit_dbus_path(u);
        if (!unit_path)
                return -ENOMEM;

        if (u->job) {
                job_path = job_dbus_path(u->job);
                if (!job_path)
                        return -ENOMEM;
        }

        return sd_bus_message_append(
                        reply, "(ssssssouso)",
                        u->id,
                        unit_description(u),
                        unit_load_state_to_string(u->load_state),
                        unit_active_state_to_string(unit_active_state(u)),
                        unit_sub_state_to_string(u),
                        following ? following->id : "",
                        unit_path,
                        u->job ? u->job->id : 0,
                        u->job ? job_type_to_string(u->job->type) : "",
                        empty_to_root(job_path));
}

static int transient_unit_from_message(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                Unit **unit,
                sd_bus_error *error) {

        UnitType t;
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(name);

        t = unit_name_to_type(name);
        if (t < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid unit name or type.");

        if (!unit_vtable[t]->can_transient)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unit type %s does not support transient units.",
                                         unit_type_to_string(t));

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        if (!unit_is_pristine(u))
                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS,
                                         "Unit %s was already loaded or has a fragment file.", name);

        /* OK, the unit failed to load and is unreferenced, now let's
         * fill in the transient data instead */
        r = unit_make_transient(u);
        if (r < 0)
                return r;

        /* Set our properties */
        r = bus_unit_set_properties(u, message, UNIT_RUNTIME, false, error);
        if (r < 0)
                return r;

        /* If the client asked for it, automatically add a reference to this unit. */
        if (u->bus_track_add) {
                r = bus_unit_track_add_sender(u, message);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch sender: %m");
        }

        /* Now load the missing bits of the unit we just created */
        unit_add_to_load_queue(u);
        manager_dispatch_load_queue(m);

        *unit = u;

        return 0;
}

static int transient_aux_units_from_message(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *error) {

        int r;

        assert(m);
        assert(message);

        r = sd_bus_message_enter_container(message, 'a', "(sa(sv))");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(message, 'r', "sa(sv)")) > 0) {
                const char *name = NULL;
                Unit *u;

                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        return r;

                r = transient_unit_from_message(m, message, name, &u, error);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        return 0;
}

static int method_start_transient_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *smode;
        Manager *m = ASSERT_PTR(userdata);
        JobMode mode;
        Unit *u;
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ss", &name, &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s is invalid.", smode);

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = transient_unit_from_message(m, message, name, &u, error);
        if (r < 0)
                return r;

        r = transient_aux_units_from_message(m, message, error);
        if (r < 0)
                return r;

        /* Finally, start it */
        return bus_unit_queue_job(message, u, JOB_START, mode, 0, error);
}

static int method_get_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;
        Job *j;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        r = mac_selinux_unit_access_check(j->unit, message, "status", error);
        if (r < 0)
                return r;

        path = job_dbus_path(j);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_cancel_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;
        Job *j;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_cancel(message, j, error);
}

static int method_clear_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_clear_jobs(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_reset_failed(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error, char **states, char **patterns) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *k;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssssouso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, k, m->units) {
                if (k != u->id)
                        continue;

                if (!strv_isempty(states) &&
                    !strv_contains(states, unit_load_state_to_string(u->load_state)) &&
                    !strv_contains(states, unit_active_state_to_string(unit_active_state(u))) &&
                    !strv_contains(states, unit_sub_state_to_string(u)))
                        continue;

                if (!strv_isempty(patterns) &&
                    !strv_fnmatch_or_empty(patterns, u->id, FNM_NOESCAPE))
                        continue;

                r = reply_unit_info(reply, u);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_units(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return list_units_filtered(message, userdata, error, NULL, NULL);
}

static int method_list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, error, states, NULL);
}

static int method_list_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(j, m->jobs) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;

                job_path = job_dbus_path(j);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(j->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(
                                reply, "(usssoo)",
                                j->id,
                                j->unit->id,
                                job_type_to_string(j->type),
                                job_state_to_string(j->state),
                                job_path,
                                unit_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_subscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {

                /* Note that direct bus connection subscribe by
                 * default, we only track peers on the API bus here */

                if (!m->subscribed) {
                        r = sd_bus_track_new(sd_bus_message_get_bus(message), &m->subscribed, NULL, NULL);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_track_add_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_set(error, BUS_ERROR_ALREADY_SUBSCRIBED, "Client is already subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unsubscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {
                r = sd_bus_track_remove_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_set(error, BUS_ERROR_NOT_SUBSCRIBED, "Client is not subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int dump_impl(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error,
                char **patterns,
                int (*reply)(sd_bus_message *, char *)) {

        _cleanup_free_ char *dump = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* 'status' access is the bare minimum always needed for this, as the policy might straight out
         * forbid a client from querying any information from systemd, regardless of any rate limiting. */
        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        /* Rate limit reached? Check if the caller is privileged/allowed by policy to bypass this. We
         * check the rate limit first to avoid the expensive roundtrip to polkit when not needed. */
        if (!ratelimit_below(&m->dump_ratelimit)) {
                /* We need a way for SELinux to constrain the operation when the rate limit is active, even
                 * if polkit would allow it, but we cannot easily add new named permissions, so we need to
                 * use an existing one. Reload/reexec are also slow but non-destructive/modifying
                 * operations, and can cause PID1 to stall. So it seems similar enough in terms of security
                 * considerations and impact, and thus use the same access check for dumps which, given the
                 * large amount of data to fetch, can stall PID1 for quite some time. */
                r = mac_selinux_access_check(message, "reload", /* error = */ NULL);
                if (r < 0)
                        goto ratelimited;

                r = bus_verify_bypass_dump_ratelimit_async(m, message, /* error = */ NULL);
                if (r < 0)
                        goto ratelimited;
                if (r == 0)
                        /* No authorization for now, but the async polkit stuff will call us again when it
                         * has it */
                        return 1;
        }

        r = manager_get_dump_string(m, patterns, &dump);
        if (r < 0)
                return r;

        return reply(message, dump);

ratelimited:
        log_warning("Dump request rejected due to rate limit on unprivileged callers, blocked for %s.",
                    FORMAT_TIMESPAN(ratelimit_left(&m->dump_ratelimit), USEC_PER_SEC));
        return sd_bus_error_setf(error,
                                 SD_BUS_ERROR_LIMITS_EXCEEDED,
                                 "Dump request rejected due to rate limit on unprivileged callers, blocked for %s.",
                                 FORMAT_TIMESPAN(ratelimit_left(&m->dump_ratelimit), USEC_PER_SEC));
}

static int reply_dump(sd_bus_message *message, char *dump) {
        return sd_bus_reply_method_return(message, "s", dump);
}

static int method_dump(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return dump_impl(message, userdata, error, NULL, reply_dump);
}

static int reply_dump_by_fd(sd_bus_message *message, char *dump) {
        _cleanup_close_ int fd = -EBADF;

        fd = acquire_data_fd(dump);
        if (fd < 0)
                return fd;

        return sd_bus_reply_method_return(message, "h", fd);
}

static int method_dump_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return dump_impl(message, userdata, error, NULL, reply_dump_by_fd);
}

// static int
// method_create_snapshot(sd_bus *bus, sd_bus_message *message, void *userdata,
// 	sd_bus_error *error)
// {
// 	_cleanup_free_ char *path = NULL;
// 	Manager *m = userdata;
// 	const char *name;
// 	int cleanup;
// 	Snapshot *s = NULL;
// 	int r;

// 	assert(bus);
// 	assert(message);
// 	assert(m);

// 	r = mac_selinux_runtime_unit_access_check(message, "start", error);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_read(message, "sb", &name, &cleanup);
// 	if (r < 0)
// 		return r;

// 	if (isempty(name))
// 		name = NULL;

// 	r = snapshot_create(m, name, cleanup, error, &s);
// 	if (r < 0)
// 		return r;

// 	path = unit_dbus_path(UNIT(s));
// 	if (!path)
// 		return -ENOMEM;

// 	return sd_bus_reply_method_return(message, "o", path);
// }

// static int
// method_remove_snapshot(sd_bus *bus, sd_bus_message *message, void *userdata,
// 	sd_bus_error *error)
// {
// 	Manager *m = userdata;
// 	const char *name;
// 	Unit *u;
// 	int r;

// 	assert(bus);
// 	assert(message);
// 	assert(m);

// 	r = mac_selinux_access_check(message, "stop", error);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_read(message, "s", &name);
// 	if (r < 0)
// 		return r;

// 	u = manager_get_unit(m, name);
// 	if (!u)
// 		return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT,
// 			"Unit %s does not exist.", name);

// 	if (u->type != UNIT_SNAPSHOT)
// 		return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT,
// 			"Unit %s is not a snapshot", name);

// 	return bus_snapshot_method_remove(bus, message, u, error);
// }

static int get_run_space(uint64_t *ret, sd_bus_error *error) {
        struct statvfs svfs;

        assert(ret);

        if (statvfs(SVC_PKGRUNSTATEDIR, &svfs) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to statvfs(/run/systemd): %m");

        *ret = (uint64_t) svfs.f_bfree * (uint64_t) svfs.f_bsize;
        return 0;
}

static int verify_run_space(const char *message, sd_bus_error *error) {
        uint64_t available = 0; /* unnecessary, but used to trick out gcc's incorrect maybe-uninitialized warning */
        int r;

        assert(message);

        r = get_run_space(&available, error);
        if (r < 0)
                return r;

        if (available < RELOAD_DISK_SPACE_MIN)
                return sd_bus_error_setf(error,
                                         BUS_ERROR_DISK_FULL,
                                         "%s, not enough space available on /run/systemd/. "
                                         "Currently, %s are free, but a safety buffer of %s is enforced.",
                                         message,
                                         FORMAT_BYTES(available),
                                         FORMAT_BYTES(RELOAD_DISK_SPACE_MIN));

        return 0;
}

static int verify_run_space_permissive(const char *message, sd_bus_error *error) {
        uint64_t available = 0; /* unnecessary, but used to trick out gcc's incorrect maybe-uninitialized warning */
        int r;

        assert(message);

        r = get_run_space(&available, error);
        if (r < 0)
                return r;

        if (available < RELOAD_DISK_SPACE_MIN)
                log_warning("Dangerously low amount of free space on /run/systemd/, %s.\n"
                            "Currently, %s are free, but %s are suggested. Proceeding anyway.",
                            message,
                            FORMAT_BYTES(available),
                            FORMAT_BYTES(RELOAD_DISK_SPACE_MIN));

        return 0;
}

static void log_caller(sd_bus_message *message, Manager *manager, const char *method) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        const char *comm = NULL;
        Unit *caller;
        pid_t pid;

        assert(message);
        assert(manager);
        assert(method);

        if (sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_COMM, &creds) < 0)
                return;

        /* We need at least the PID, otherwise there's nothing to log, the rest is optional */
        if (sd_bus_creds_get_pid(creds, &pid) < 0)
                return;

        (void) sd_bus_creds_get_comm(creds, &comm);
        caller = manager_get_unit_by_pid(manager, pid);

        log_info("%s requested from client PID " PID_FMT "%s%s%s%s%s%s...",
                 method, pid,
                 comm ? " ('" : "", strempty(comm), comm ? "')" : "",
                 caller ? " (unit " : "", caller ? caller->id : "", caller ? ")" : "");
}

static int method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = verify_run_space("Refusing to reload", error);
        if (r < 0)
                return r;

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Write a log message noting the unit or process who requested the Reload() */
        log_caller(message, m, "Reload");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&m->reload_reexec_ratelimit)) {
                log_warning("Reloading request rejected due to rate limit.");
                return sd_bus_error_setf(error,
                                         SD_BUS_ERROR_LIMITS_EXCEEDED,
                                         "Reload() request rejected due to rate limit.");
        }

        /* Instead of sending the reply back right away, we just
         * remember that we need to and then send it after the reload
         * is finished. That way the caller knows when the reload
         * finished. */

        assert(!m->pending_reload_message);
        r = sd_bus_message_new_method_return(message, &m->pending_reload_message);
        if (r < 0)
                return r;

        m->objective = MANAGER_RELOAD;

        return 1;
}

static int method_reexecute(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = verify_run_space("Refusing to reexecute", error);
        if (r < 0)
                return r;

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Write a log message noting the unit or process who requested the Reexecute() */
        log_caller(message, m, "Reexecution");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&m->reload_reexec_ratelimit)) {
                log_warning("Reexecution request rejected due to rate limit.");
                return sd_bus_error_setf(error,
                                         SD_BUS_ERROR_LIMITS_EXCEEDED,
                                         "Reexecute() request rejected due to rate limit.");
        }

        /* We don't send a reply back here, the client should
         * just wait for us disconnecting. */

        m->objective = MANAGER_REEXECUTE;
        return 1;
}

static int method_exit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        /* Exit() (in contrast to SetExitCode()) is actually allowed even if
         * we are running on the host. It will fall back on reboot() in
         * systemd-shutdown if it cannot do the exit() because it isn't a
         * container. */

        m->objective = MANAGER_EXIT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "Reboot is only supported for system managers.");

        m->objective = MANAGER_REBOOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "Powering off is only supported for system managers.");

        m->objective = MANAGER_POWEROFF;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_halt(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "Halt is only supported for system managers.");

        m->objective = MANAGER_HALT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kexec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "KExec is only supported for system managers.");

        m->objective = MANAGER_KEXEC;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_root(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *ri = NULL, *rt = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *root, *init;
        int r;

        assert(message);

        r = verify_run_space_permissive("root switching may fail", error);
        if (r < 0)
                return r;

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "Root switching is only supported by system manager.");

        r = sd_bus_message_read(message, "ss", &root, &init);
        if (r < 0)
                return r;

        if (isempty(root))
                /* If path is not specified, default to "/sysroot" which is what we generally expect initrds
                 * to use */
                root = "/sysroot";
        else {
                if (!path_is_valid(root))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root directory must be a valid path.");

                if (!path_is_absolute(root))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root path '%s' is not absolute.", root);

                r = path_is_root(root);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r,
                                                       "Failed to check if new root directory '%s' is the same as old root: %m",
                                                       root);
                if (r > 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root directory cannot be the old root directory.");
        }

        /* Safety check */
        if (!in_initrd())
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Not in initrd, refusing switch-root operation.");

        r = path_is_os_tree(root);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r,
                                               "Failed to determine whether root path '%s' contains an OS tree: %m",
                                               root);
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Specified switch root path '%s' does not seem to be an OS tree. os-release file is missing.",
                                         root);

        if (!isempty(init)) {
                if (!path_is_valid(init))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Path to init binary '%s' is not a valid path.", init);

                if (!path_is_absolute(init))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Path to init binary '%s' not absolute.", init);

                r = chase_and_access(init, root, CHASE_PREFIX_ROOT, X_OK, NULL);
                if (r == -EACCES)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Init binary %s is not executable.", init);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r,
                                                       "Could not resolve init executable %s: %m", init);
        }

        rt = strdup(root);
        if (!rt)
                return -ENOMEM;

        if (!isempty(init)) {
                ri = strdup(init);
                if (!ri)
                        return -ENOMEM;
        }

        free_and_replace(m->switch_root, rt);
        free_and_replace(m->switch_root_init, ri);

        m->objective = MANAGER_SWITCH_ROOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **plus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(plus))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, NULL, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid environment variable names or assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, NULL);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_and_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL, **plus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid environment variable names or assignments");
        if (!strv_env_is_valid(plus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *error, char **states, char **patterns) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        UnitFileList *item;
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        h = hashmap_new(&unit_file_list_hash_ops_free);
        if (!h)
                return -ENOMEM;

        r = unit_file_get_list(m->runtime_scope, NULL, h, states, patterns);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(item, h) {

                r = sd_bus_message_append(reply, "(ss)", item->path, unit_file_state_to_string(item->state));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return list_unit_files_by_patterns(message, userdata, error, NULL, NULL);
}

static int method_list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return list_unit_files_by_patterns(message, userdata, error, states, patterns);
}

static int method_get_unit_file_state(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        UnitFileState state;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = unit_file_get_state(m->runtime_scope, NULL, name, &state);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", unit_file_state_to_string(state));
}

static int method_get_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *default_target = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = unit_file_get_default(m->runtime_scope, NULL, &default_target);
        if (r == -ERFKILL)
                sd_bus_error_setf(error, BUS_ERROR_UNIT_MASKED, "Unit file is masked.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", default_target);
}

static int send_unit_files_changed(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message,
                                      "/org/freedesktop/systemd1",
                                      SVC_DBUS_INTERFACE ".Manager",
                                      "UnitFilesChanged");
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

static void manager_unit_files_changed(Manager *m, const InstallChange *changes, size_t n_changes) {
        int r;

        assert(m);
        assert(changes || n_changes == 0);

        if (!install_changes_have_modification(changes, n_changes))
                return;

        /* See comments for this variable in manager.h */
        m->unit_file_state_outdated = true;

        r = bus_foreach_bus(m, NULL, send_unit_files_changed, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send UnitFilesChanged signal, ignoring: %m");
}

static int install_error(
                sd_bus_error *error,
                int c,
                InstallChange *changes,
                size_t n_changes) {

        int r;

        /* Create an error reply, using the error information from changes[] if possible, and fall back to
         * generating an error from error code c. The error message only describes the first error. */

        assert(changes || n_changes == 0);

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        FOREACH_ARRAY(i, changes, n_changes) {
                _cleanup_free_ char *err_message = NULL;
                const char *bus_error;

                if (i->type >= 0)
                        continue;

                r = install_change_dump_error(i, &err_message, &bus_error);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "File %s: %m", i->path);

                return sd_bus_error_set(error, bus_error, err_message);
        }

        return c < 0 ? c : -EINVAL;
}

static int reply_install_changes_and_free(
                Manager *m,
                sd_bus_message *message,
                int carries_install_info,
                InstallChange *changes,
                size_t n_changes,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        bool bad = false, good = false;
        int r;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        if (carries_install_info >= 0) {
                r = sd_bus_message_append(reply, "b", carries_install_info);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_open_container(reply, 'a', "(sss)");
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, changes, n_changes) {
                if (i->type < 0) {
                        bad = true;
                        continue;
                }

                r = sd_bus_message_append(
                                reply, "(sss)",
                                install_change_type_to_string(i->type),
                                i->path,
                                i->source);
                if (r < 0)
                        return r;

                good = true;
        }

        /* If there was a failed change, and no successful change, then return the first failure as proper
         * method call error. */
        if (bad && !good)
                return install_error(error, 0, TAKE_PTR(changes), n_changes);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_enable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char *files[], InstallChange **changes, size_t *n_changes),
                bool carries_install_info,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileFlags flags;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "EnableUnitFilesWithFlags")) {
                uint64_t raw_flags;

                r = sd_bus_message_read(message, "t", &raw_flags);
                if (r < 0)
                        return r;
                if ((raw_flags & ~_UNIT_FILE_FLAGS_MASK_PUBLIC) != 0)
                        return -EINVAL;
                flags = raw_flags;
        } else {
                int runtime, force;

                r = sd_bus_message_read(message, "bb", &runtime, &force);
                if (r < 0)
                        return r;
                flags = unit_file_bools_to_flags(runtime, force);
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->runtime_scope, flags, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes, error);
}

static int method_enable_unit_files_with_flags(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_enable, /* carries_install_info = */ true, error);
}

static int method_enable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_enable, /* carries_install_info = */ true, error);
}

static int method_reenable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_reenable, /* carries_install_info = */ true, error);
}

static int method_link_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_link, /* carries_install_info = */ false, error);
}

static int unit_file_preset_without_mode(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char **files, InstallChange **changes, size_t *n_changes) {
        return unit_file_preset(scope, flags, root_dir, files, UNIT_FILE_PRESET_FULL, changes, n_changes);
}

static int method_preset_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_preset_without_mode, /* carries_install_info = */ true, error);
}

static int method_mask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_mask, /* carries_install_info = */ false, error);
}

static int method_preset_unit_files_with_mode(sd_bus_message *message, void *userdata, sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        UnitFilePresetMode preset_mode;
        int runtime, force, r;
        UnitFileFlags flags;
        const char *mode;

        assert(message);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                preset_mode = UNIT_FILE_PRESET_FULL;
        else {
                preset_mode = unit_file_preset_mode_from_string(mode);
                if (preset_mode < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset(m->runtime_scope, flags, NULL, l, preset_mode, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, r, changes, n_changes, error);
}

static int method_disable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char *files[], InstallChange **changes, size_t *n_changes),
                bool carries_install_info,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        UnitFileFlags flags;
        size_t n_changes = 0;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "DisableUnitFilesWithFlags") ||
            sd_bus_message_is_method_call(message, NULL, "DisableUnitFilesWithFlagsAndInstallInfo")) {
                uint64_t raw_flags;

                r = sd_bus_message_read(message, "t", &raw_flags);
                if (r < 0)
                        return r;
                if ((raw_flags & ~_UNIT_FILE_FLAGS_MASK_PUBLIC) != 0 ||
                                FLAGS_SET(raw_flags, UNIT_FILE_FORCE))
                        return -EINVAL;
                flags = raw_flags;
        } else {
                int runtime;

                r = sd_bus_message_read(message, "b", &runtime);
                if (r < 0)
                        return r;
                flags = unit_file_bools_to_flags(runtime, false);
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->runtime_scope, flags, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes, error);
}

static int method_disable_unit_files_with_flags(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info = */ false, error);
}

static int method_disable_unit_files_with_flags_and_install_info(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info = */ true, error);
}

static int method_disable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info = */ false, error);
}

static int method_unmask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_unmask, /* carries_install_info = */ false, error);
}

static int method_revert_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_revert(m->runtime_scope, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_set_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        int force, r;

        assert(message);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sb", &name, &force);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_set_default(m->runtime_scope, force ? UNIT_FILE_FORCE : 0, NULL, name, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_preset_all_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        UnitFilePresetMode preset_mode;
        const char *mode;
        UnitFileFlags flags;
        int force, runtime, r;

        assert(message);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                preset_mode = UNIT_FILE_PRESET_FULL;
        else {
                preset_mode = unit_file_preset_mode_from_string(mode);
                if (preset_mode < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset_all(m->runtime_scope, flags, NULL, preset_mode, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_add_dependency_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        int runtime, force, r;
        char *target, *type;
        UnitDependency dep;
        UnitFileFlags flags;

        assert(message);

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ssbb", &target, &type, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        dep = unit_dependency_from_string(type);
        if (dep < 0)
                return -EINVAL;

        r = unit_file_add_dependency(m->runtime_scope, flags, NULL, l, target, dep, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_get_unit_file_links(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        InstallChange *changes = NULL;
        size_t n_changes = 0, i;
        const char *name;
        int runtime, r;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        r = sd_bus_message_read(message, "sb", &name, &runtime);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return r;

        r = unit_file_disable(m->runtime_scope,
                              UNIT_FILE_DRY_RUN | (runtime ? UNIT_FILE_RUNTIME : 0),
                              NULL, STRV_MAKE(name), &changes, &n_changes);
        if (r < 0)
                return log_error_errno(r, "Failed to get file links for %s: %m", name);

        for (i = 0; i < n_changes; i++)
                if (changes[i].type == INSTALL_CHANGE_UNLINK) {
                        r = sd_bus_message_append(reply, "s", changes[i].path);
                        if (r < 0)
                                return r;
                }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

const sd_bus_vtable bus_manager_vtable[] = { SD_BUS_VTABLE_START(0),

	SD_BUS_PROPERTY("Version", "s", property_get_version, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Features", "s", property_get_features, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Virtualization", "s", property_get_virtualization, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Architecture", "s", property_get_architecture, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Tainted", "s", property_get_tainted, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("FirmwareTimestamp",
		offsetof(Manager, firmware_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("LoaderTimestamp",
		offsetof(Manager, loader_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("KernelTimestamp",
		offsetof(Manager, kernel_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("InitRDTimestamp",
		offsetof(Manager, initrd_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("UserspaceTimestamp",
		offsetof(Manager, userspace_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("FinishTimestamp",
		offsetof(Manager, finish_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("SecurityStartTimestamp",
		offsetof(Manager, security_start_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("SecurityFinishTimestamp",
		offsetof(Manager, security_finish_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsStartTimestamp",
		offsetof(Manager, generators_start_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsFinishTimestamp",
		offsetof(Manager, generators_finish_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadStartTimestamp",
		offsetof(Manager, units_load_start_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadFinishTimestamp",
		offsetof(Manager, units_load_finish_timestamp),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", property_get_log_level,
		property_set_log_level, 0, 0),
	SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", property_get_log_target,
		property_set_log_target, 0, 0),
	SD_BUS_PROPERTY("NNames", "u", property_get_n_names, 0, 0),
	SD_BUS_PROPERTY("NFailedUnits", "u", property_get_n_failed_units, 0, 0),
	SD_BUS_PROPERTY("NJobs", "u", property_get_n_jobs, 0, 0),
	SD_BUS_PROPERTY("NInstalledJobs", "u", bus_property_get_unsigned,
		offsetof(Manager, n_installed_jobs), 0),
	SD_BUS_PROPERTY("NFailedJobs", "u", bus_property_get_unsigned,
		offsetof(Manager, n_failed_jobs), 0),
	SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),
	SD_BUS_PROPERTY("Environment", "as", NULL,
		offsetof(Manager, environment), 0),
	SD_BUS_PROPERTY("ConfirmSpawn", "b", bus_property_get_bool,
		offsetof(Manager, confirm_spawn), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ShowStatus", "b", bus_property_get_bool,
		offsetof(Manager, show_status), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("UnitPath", "as", NULL, offsetof(Manager, lookup_paths.search_path), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultStandardOutput", "s",
		bus_property_get_exec_output,
		offsetof(Manager, default_std_output),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultStandardError", "s",
		bus_property_get_exec_output,
		offsetof(Manager, default_std_output),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogUSec", "t",
		bus_property_get_usec, property_set_runtime_watchdog,
		offsetof(Manager, runtime_watchdog), 0),
	SD_BUS_WRITABLE_PROPERTY("ShutdownWatchdogUSec", "t",
		bus_property_get_usec, bus_property_set_usec,
		offsetof(Manager, shutdown_watchdog), 0),
	SD_BUS_PROPERTY("ControlGroup", "s", NULL,
		offsetof(Manager, cgroup_root), 0),
	SD_BUS_PROPERTY("SystemState", "s", property_get_system_state, 0, 0),
	SD_BUS_PROPERTY("DefaultTimerAccuracyUSec", "t", bus_property_get_usec,
		offsetof(Manager, default_timer_accuracy_usec),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultTimeoutStartUSec", "t", bus_property_get_usec,
		offsetof(Manager, default_timeout_start_usec),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultTimeoutStopUSec", "t", bus_property_get_usec,
		offsetof(Manager, default_timeout_stop_usec),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultRestartUSec", "t", bus_property_get_usec,
		offsetof(Manager, default_restart_usec),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultStartLimitInterval", "t", bus_property_get_usec,
		offsetof(Manager, default_start_limit_interval),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultStartLimitBurst", "u",
		bus_property_get_unsigned,
		offsetof(Manager, default_start_limit_burst),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultCPUAccounting", "b", bus_property_get_bool,
		offsetof(Manager, default_cpu_accounting),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultBlockIOAccounting", "b", bus_property_get_bool,
		offsetof(Manager, default_blockio_accounting),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultMemoryAccounting", "b", bus_property_get_bool,
		offsetof(Manager, default_memory_accounting),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultTasksAccounting", "b", bus_property_get_bool,
		offsetof(Manager, default_tasks_accounting),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitCPU", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_CPU]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitFSIZE", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_FSIZE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitDATA", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_DATA]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitSTACK", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_STACK]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitCORE", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_CORE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitRSS", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_RSS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitNOFILE", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_NOFILE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
#ifdef RLIMIT_AS
	SD_BUS_PROPERTY("DefaultLimitAS", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_AS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
#endif
	SD_BUS_PROPERTY("DefaultLimitNPROC", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_NPROC]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitMEMLOCK", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_MEMLOCK]),
		SD_BUS_VTABLE_PROPERTY_CONST),
#ifdef SVC_PLATFORM_Linux
	SD_BUS_PROPERTY("DefaultLimitLOCKS", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_LOCKS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitSIGPENDING", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_SIGPENDING]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitMSGQUEUE", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_MSGQUEUE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitNICE", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_NICE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitRTPRIO", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_RTPRIO]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultLimitRTTIME", "t", bus_property_get_rlimit,
		offsetof(Manager, rlimit[RLIMIT_RTTIME]),
		SD_BUS_VTABLE_PROPERTY_CONST),
#endif
	SD_BUS_PROPERTY("DefaultTasksMax", "t", NULL,
		offsetof(Manager, default_tasks_max),
		SD_BUS_VTABLE_PROPERTY_CONST),

	SD_BUS_METHOD("GetUnit", "s", "o", method_get_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetUnitByPID", "u", "o", method_get_unit_by_pid,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("LoadUnit", "s", "o", method_load_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("StartUnit", "ss", "o", method_start_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("StartUnitReplace", "sss", "o", method_start_unit_replace,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("StopUnit", "ss", "o", method_stop_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ReloadUnit", "ss", "o", method_reload_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("RestartUnit", "ss", "o", method_restart_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("TryRestartUnit", "ss", "o", method_try_restart_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ReloadOrRestartUnit", "ss", "o",
		method_reload_or_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ReloadOrTryRestartUnit", "ss", "o",
		method_reload_or_try_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("KillUnit", "ssi", NULL, method_kill_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ResetFailedUnit", "s", NULL, method_reset_failed_unit,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("SetUnitProperties", "sba(sv)", NULL,
		method_set_unit_properties, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("StartTransientUnit", "ssa(sv)a(sa(sv))", "o",
		method_start_transient_unit, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetJob", "u", "o", method_get_job,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("CancelJob", "u", NULL, method_cancel_job,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ClearJobs", NULL, NULL, method_clear_jobs, 0),
	SD_BUS_METHOD("ResetFailed", NULL, NULL, method_reset_failed, 0),
	SD_BUS_METHOD("ListUnits", NULL, "a(ssssssouso)", method_list_units,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ListUnitsFiltered", "as", "a(ssssssouso)",
		method_list_units_filtered, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ListJobs", NULL, "a(usssoo)", method_list_jobs,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Subscribe", NULL, NULL, method_subscribe,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Unsubscribe", NULL, NULL, method_unsubscribe,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Dump", NULL, "s", method_dump,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("DumpByFileDescriptor", NULL, "h", method_dump_by_fd,
		SD_BUS_VTABLE_UNPRIVILEGED),
	// SD_BUS_METHOD("CreateSnapshot", "sb", "o", method_create_snapshot, 0),
	// SD_BUS_METHOD("RemoveSnapshot", "s", NULL, method_remove_snapshot, 0),
	SD_BUS_METHOD("Reload", NULL, NULL, method_reload,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Reexecute", NULL, NULL, method_reexecute,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Exit", NULL, NULL, method_exit, 0),
	SD_BUS_METHOD("Reboot", NULL, NULL, method_reboot,
		SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
	SD_BUS_METHOD("PowerOff", NULL, NULL, method_poweroff,
		SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
	SD_BUS_METHOD("Halt", NULL, NULL, method_halt,
		SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
	SD_BUS_METHOD("KExec", NULL, NULL, method_kexec,
		SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
	SD_BUS_METHOD("SwitchRoot", "ss", NULL, method_switch_root,
		SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
	SD_BUS_METHOD("SetEnvironment", "as", NULL, method_set_environment, 0),
	SD_BUS_METHOD("UnsetEnvironment", "as", NULL, method_unset_environment,
		0),
	SD_BUS_METHOD("UnsetAndSetEnvironment", "asas", NULL,
		method_unset_and_set_environment, 0),
	SD_BUS_METHOD("ListUnitFiles", NULL, "a(ss)", method_list_unit_files,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetUnitFileState", "s", "s", method_get_unit_file_state,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("EnableUnitFiles", "asbb", "ba(sss)",
		method_enable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("DisableUnitFiles", "asb", "a(sss)",
		method_disable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("ReenableUnitFiles", "asbb", "ba(sss)",
		method_reenable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("LinkUnitFiles", "asbb", "a(sss)", method_link_unit_files,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("PresetUnitFiles", "asbb", "ba(sss)",
		method_preset_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("PresetUnitFilesWithMode", "assbb", "ba(sss)",
		method_preset_unit_files_with_mode, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("MaskUnitFiles", "asbb", "a(sss)", method_mask_unit_files,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("UnmaskUnitFiles", "asb", "a(sss)",
		method_unmask_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("SetDefaultTarget", "sb", "a(sss)",
		method_set_default_target, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetDefaultTarget", NULL, "s", method_get_default_target,
		SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("PresetAllUnitFiles", "sbb", "a(sss)",
		method_preset_all_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("AddDependencyUnitFiles", "asssbb", "a(sss)",
		method_add_dependency_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetUnitFileLinks", "sb", "as",
		method_get_unit_file_links, SD_BUS_VTABLE_UNPRIVILEGED),

	SD_BUS_SIGNAL("UnitNew", "so", 0),
	SD_BUS_SIGNAL("UnitRemoved", "so", 0),
	SD_BUS_SIGNAL("JobNew", "uos", 0),
	SD_BUS_SIGNAL("JobRemoved", "uoss", 0),
	SD_BUS_SIGNAL("StartupFinished", "tttttt", 0),
	SD_BUS_SIGNAL("UnitFilesChanged", NULL, 0),
	SD_BUS_SIGNAL("Reloading", "b", 0),

	SD_BUS_VTABLE_END };

static int send_finished(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        usec_t *times = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus,
                                      &message,
                                      "/org/freedesktop/systemd1",
                                      SVC_DBUS_INTERFACE ".Manager",
                                      "StartupFinished");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "tttttt", times[0], times[1], times[2], times[3], times[4], times[5]);
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void
bus_manager_send_finished(Manager *m, usec_t firmware_usec, usec_t loader_usec,
	usec_t kernel_usec, usec_t initrd_usec, usec_t userspace_usec,
	usec_t total_usec)
{
	int r;

	assert(m);

	r = bus_foreach_bus(m, NULL, send_finished,
		(usec_t[6]){ firmware_usec, loader_usec, kernel_usec,
			initrd_usec, userspace_usec, total_usec });
	if (r < 0)
		log_debug_errno(r, "Failed to send finished signal: %m");
}

static int send_reloading(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", SVC_DBUS_INTERFACE ".Manager", "Reloading");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "b", PTR_TO_INT(userdata));
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void
bus_manager_send_reloading(Manager *m, bool active)
{
	int r;

	assert(m);

	r = bus_foreach_bus(m, NULL, send_reloading, INT_TO_PTR(active));
	if (r < 0)
		log_debug_errno(r, "Failed to send reloading signal: %m");
}
