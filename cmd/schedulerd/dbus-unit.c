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

#include "alloc-util.h"
#include "dbus-unit.h"
#include "bsdsignal.h"
#include "bus-common-errors.h"
#include "cgroup-util.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-util.h"
#include "dbus.h"
#include "fileio.h"
#include "locale-util.h"
#include "log.h"
#include "path-util.h"
#include "sd-bus.h"
#include "selinux-access.h"
#include "signal-util.h"
#include "special.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_load_state, unit_load_state,
	UnitLoadState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_job_mode, job_mode, JobMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_emergency_action,
	emergency_action, EmergencyAction);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_collect_mode, collect_mode,
	CollectMode);

static int
property_get_names(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;
	Iterator i;
	const char *t;
	int r;

	assert(bus);
	assert(reply);
	assert(u);

	r = sd_bus_message_open_container(reply, 'a', "s");
	if (r < 0)
		return r;

	SET_FOREACH (t, u->names) {
		r = sd_bus_message_append(reply, "s", t);
		if (r < 0)
			return r;
	}

	return sd_bus_message_close_container(reply);
}

static int
property_get_following(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata, *f;

	assert(bus);
	assert(reply);
	assert(u);

	f = unit_following(u);
	return sd_bus_message_append(reply, "s", f ? f->id : "");
}

static int
property_get_dependencies(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Set *s = *(Set **)userdata;
	Iterator j;
	Unit *u;
	int r;

	assert(bus);
	assert(reply);

	r = sd_bus_message_open_container(reply, 'a', "s");
	if (r < 0)
		return r;

	SET_FOREACH (u, s) {
		r = sd_bus_message_append(reply, "s", u->id);
		if (r < 0)
			return r;
	}

	return sd_bus_message_close_container(reply);
}

static int
property_get_description(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "s", unit_description(u));
}

static int
property_get_active_state(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "s",
		unit_active_state_to_string(unit_active_state(u)));
}

static int
property_get_sub_state(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "s", unit_sub_state_to_string(u));
}

static int
property_get_unit_file_preset(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error)
{
	Unit *u = userdata;
	int r;

	assert(bus);
	assert(reply);
	assert(u);

	r = unit_get_unit_file_preset(u);

	return sd_bus_message_append(reply, "s",
		r < 0	      ? "" :
			r > 0 ? "enabled" :
				      "disabled");
}

static int
property_get_unit_file_state(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "s",
		unit_file_state_to_string(unit_get_unit_file_state(u)));
}

static int
property_get_can_start(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "b",
		unit_can_start(u) && !u->refuse_manual_start);
}

static int
property_get_can_stop(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	/* On the lower levels we assume that every unit we can start
         * we can also stop */

	return sd_bus_message_append(reply, "b",
		unit_can_start(u) && !u->refuse_manual_stop);
}

static int
property_get_can_reload(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "b", unit_can_reload(u));
}

static int
property_get_can_isolate(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "b",
		unit_can_isolate(u) && !u->refuse_manual_start);
}

static int
property_get_job(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	_cleanup_free_ char *p = NULL;
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	if (!u->job)
		return sd_bus_message_append(reply, "(uo)", 0, "/");

	p = job_dbus_path(u->job);
	if (!p)
		return -ENOMEM;

	return sd_bus_message_append(reply, "(uo)", u->job->id, p);
}

static int
property_get_need_daemon_reload(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "b", unit_need_daemon_reload(u));
}

static int
property_get_conditions(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	const char *(*to_string)(ConditionType type) = NULL;
	Condition **list = userdata, *c;
	int r;

	assert(bus);
	assert(reply);
	assert(list);

	to_string = streq(property, "Asserts") ? assert_type_to_string :
						       condition_type_to_string;

	r = sd_bus_message_open_container(reply, 'a', "(sbbsi)");
	if (r < 0)
		return r;

	LIST_FOREACH (conditions, c, *list) {
		int tristate;

		tristate = c->result == CONDITION_UNTESTED ? 0 :
			c->result == CONDITION_SUCCEEDED   ? 1 :
								   -1;

		r = sd_bus_message_append(reply, "(sbbsi)", to_string(c->type),
			c->trigger, c->negate, c->parameter, tristate);
		if (r < 0)
			return r;
	}

	return sd_bus_message_close_container(reply);
}

static int property_get_load_error(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = bus_unit_validate_load_state(u, &e);
        if (r < 0)
                return sd_bus_message_append(reply, "(ss)", e.name, e.message);

        return sd_bus_message_append(reply, "(ss)", NULL, NULL);
}

static const char *const polkit_message_for_job[_JOB_TYPE_MAX] = {
        [JOB_START]       = N_("Authentication is required to start '$(unit)'."),
        [JOB_STOP]        = N_("Authentication is required to stop '$(unit)'."),
        [JOB_RELOAD]      = N_("Authentication is required to reload '$(unit)'."),
        [JOB_RESTART]     = N_("Authentication is required to restart '$(unit)'."),
        [JOB_TRY_RESTART] = N_("Authentication is required to restart '$(unit)'."),
};

int bus_unit_method_start_generic(
                sd_bus_message *message,
                Unit *u,
                JobType job_type,
                bool reload_if_possible,
                sd_bus_error *error) {

        BusUnitQueueFlags job_flags = reload_if_possible ? BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE : 0;
        const char *smode, *verb;
        JobMode mode;
        int r;

        assert(message);
        assert(u);
        assert(job_type >= 0 && job_type < _JOB_TYPE_MAX);

        r = mac_selinux_unit_access_check(
                        u, message,
                        job_type_to_access_method(job_type),
                        error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s invalid", smode);

        if (reload_if_possible)
                verb = strjoina("reload-or-", job_type_to_string(job_type));
        else
                verb = job_type_to_string(job_type);

        if (sd_bus_message_is_method_call(message, NULL, "StartUnitWithFlags")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "t", &input_flags);
                if (r < 0)
                        return r;
                /* Let clients know that this version doesn't support any flags at the moment. */
                if (input_flags != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
        }

        r = bus_verify_manage_units_async_full(
                        u,
                        verb,
                        polkit_message_for_job[job_type],
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        return bus_unit_queue_job(message, u, job_type, mode, job_flags, error);
}

static int bus_unit_method_start(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_START, false, error);
}

static int bus_unit_method_stop(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_STOP, false, error);
}

static int bus_unit_method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RELOAD, false, error);
}

static int bus_unit_method_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, false, error);
}

static int bus_unit_method_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, false, error);
}

static int bus_unit_method_reload_or_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, true, error);
}

static int bus_unit_method_reload_or_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, true, error);
}

int bus_unit_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = ASSERT_PTR(userdata);
        int32_t value = 0;
        const char *swho;
        int32_t signo;
        KillWho who;
        int r, code;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "stop", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "si", &swho, &signo);
        if (r < 0)
                return r;

        if (startswith(sd_bus_message_get_member(message), "QueueSignal")) {
                r = sd_bus_message_read(message, "i", &value);
                if (r < 0)
                        return r;

                code = SI_QUEUE;
        } else
                code = SI_USER;

        if (isempty(swho))
                who = KILL_ALL;
        else {
                who = kill_who_from_string(swho);
                if (who < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid who argument: %s", swho);
        }

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Signal number out of range.");

        if (code == SI_QUEUE && !((signo >= SIGRTMIN) && (signo <= SIGRTMAX)))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Value parameter only accepted for realtime signals (SIGRTMIN…SIGRTMAX), refusing for signal SIG%s.", signal_to_string(signo));

        r = bus_verify_manage_units_async_full(
                        u,
                        "kill",
                        N_("Authentication is required to send a UNIX signal to the processes of '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_kill(u, who, signo, code, value, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "reset-failed",
                        N_("Authentication is required to reset the \"failed\" state of '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        unit_reset_failed(u);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_set_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = ASSERT_PTR(userdata);
        int runtime, r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "set-property",
                        N_("Authentication is required to set properties on '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = bus_unit_set_properties(u, message, runtime ? UNIT_RUNTIME : UNIT_PERSISTENT, true, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable bus_unit_vtable[] = { SD_BUS_VTABLE_START(0),

	SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Unit, id),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Names", "as", property_get_names, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Following", "s", property_get_following, 0, 0),
	SD_BUS_PROPERTY("Requires", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUIRES]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RequiresOverridable", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUIRES_OVERRIDABLE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Requisite", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUISITE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RequisiteOverridable", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUISITE_OVERRIDABLE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Wants", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_WANTS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("BindsTo", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_BINDS_TO]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("PartOf", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_PART_OF]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RequiredBy", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUIRED_BY]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RequiredByOverridable", "as",
		property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_REQUIRED_BY_OVERRIDABLE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("WantedBy", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_WANTED_BY]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("BoundBy", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_BOUND_BY]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ConsistsOf", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_CONSISTS_OF]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Conflicts", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_CONFLICTS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ConflictedBy", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_CONFLICTED_BY]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Before", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_BEFORE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("After", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_AFTER]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("OnFailure", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_ON_FAILURE]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Triggers", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_TRIGGERS]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("TriggeredBy", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_TRIGGERED_BY]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("PropagatesReloadTo", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_PROPAGATES_RELOAD_TO]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ReloadPropagatedFrom", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_RELOAD_PROPAGATED_FROM]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("JoinsNamespaceOf", "as", property_get_dependencies,
		offsetof(Unit, dependencies[UNIT_JOINS_NAMESPACE_OF]),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RequiresMountsFor", "as", NULL,
		offsetof(Unit, requires_mounts_for),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Documentation", "as", NULL,
		offsetof(Unit, documentation), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Description", "s", property_get_description, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("LoadState", "s", property_get_load_state,
		offsetof(Unit, load_state), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ActiveState", "s", property_get_active_state, 0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("SubState", "s", property_get_sub_state, 0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("FragmentPath", "s", NULL,
		offsetof(Unit, fragment_path), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("SourcePath", "s", NULL, offsetof(Unit, source_path),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DropInPaths", "as", NULL, offsetof(Unit, dropin_paths),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("UnitFileState", "s", property_get_unit_file_state, 0,
		0),
	SD_BUS_PROPERTY("UnitFilePreset", "s", property_get_unit_file_preset, 0,
		0),
	BUS_PROPERTY_DUAL_TIMESTAMP("InactiveExitTimestamp",
		offsetof(Unit, inactive_exit_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	BUS_PROPERTY_DUAL_TIMESTAMP("ActiveEnterTimestamp",
		offsetof(Unit, active_enter_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	BUS_PROPERTY_DUAL_TIMESTAMP("ActiveExitTimestamp",
		offsetof(Unit, active_exit_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	BUS_PROPERTY_DUAL_TIMESTAMP("InactiveEnterTimestamp",
		offsetof(Unit, inactive_enter_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("CanStart", "b", property_get_can_start, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("CanStop", "b", property_get_can_stop, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("CanReload", "b", property_get_can_reload, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("CanIsolate", "b", property_get_can_isolate, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Job", "(uo)", property_get_job, 0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("StopWhenUnneeded", "b", bus_property_get_bool,
		offsetof(Unit, stop_when_unneeded),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RefuseManualStart", "b", bus_property_get_bool,
		offsetof(Unit, refuse_manual_start),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("RefuseManualStop", "b", bus_property_get_bool,
		offsetof(Unit, refuse_manual_stop),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("AllowIsolate", "b", bus_property_get_bool,
		offsetof(Unit, allow_isolate), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("DefaultDependencies", "b", bus_property_get_bool,
		offsetof(Unit, default_dependencies),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("OnFailureJobMode", "s", property_get_job_mode,
		offsetof(Unit, on_failure_job_mode),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("IgnoreOnIsolate", "b", bus_property_get_bool,
		offsetof(Unit, ignore_on_isolate),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("IgnoreOnSnapshot", "b", bus_property_get_bool,
		offsetof(Unit, ignore_on_snapshot),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("NeedDaemonReload", "b",
		property_get_need_daemon_reload, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("JobTimeoutUSec", "t", bus_property_get_usec,
		offsetof(Unit, job_timeout), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("JobTimeoutAction", "s", property_get_emergency_action,
		offsetof(Unit, job_timeout_action),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("JobTimeoutRebootArgument", "s", NULL,
		offsetof(Unit, job_timeout_reboot_arg),
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("ConditionResult", "b", bus_property_get_bool,
		offsetof(Unit, condition_result),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("AssertResult", "b", bus_property_get_bool,
		offsetof(Unit, assert_result),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	BUS_PROPERTY_DUAL_TIMESTAMP("ConditionTimestamp",
		offsetof(Unit, condition_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	BUS_PROPERTY_DUAL_TIMESTAMP("AssertTimestamp",
		offsetof(Unit, assert_timestamp),
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("Conditions", "a(sbbsi)", property_get_conditions,
		offsetof(Unit, conditions), 0),
	SD_BUS_PROPERTY("Asserts", "a(sbbsi)", property_get_conditions,
		offsetof(Unit, asserts), 0),
	SD_BUS_PROPERTY("LoadError", "(ss)", property_get_load_error, 0,
		SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Transient", "b", bus_property_get_bool,
		offsetof(Unit, transient), SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("CollectMode", "s", property_get_collect_mode,
		offsetof(Unit, collect_mode), SD_BUS_VTABLE_PROPERTY_CONST),

	SD_BUS_METHOD("Start", "s", "o", bus_unit_method_start, 0),
	SD_BUS_METHOD("Stop", "s", "o", bus_unit_method_stop, 0),
	SD_BUS_METHOD("Reload", "s", "o", bus_unit_method_reload, 0),
	SD_BUS_METHOD("Restart", "s", "o", bus_unit_method_restart, 0),
	SD_BUS_METHOD("TryRestart", "s", "o", bus_unit_method_try_restart, 0),
	SD_BUS_METHOD("ReloadOrRestart", "s", "o", bus_unit_method_reload_or_restart, 0),
	SD_BUS_METHOD("ReloadOrTryRestart", "s", "o",
		bus_unit_method_reload_or_try_restart, 0),
	SD_BUS_METHOD("Kill", "si", NULL, bus_unit_method_kill, 0),
	SD_BUS_METHOD("ResetFailed", NULL, NULL, bus_unit_method_reset_failed,
		0),
	SD_BUS_METHOD("SetProperties", "ba(sv)", NULL,
		bus_unit_method_set_properties, 0),

	SD_BUS_VTABLE_END };

static int
property_get_slice(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	Unit *u = userdata;

	assert(bus);
	assert(reply);
	assert(u);

	return sd_bus_message_append(reply, "s", unit_slice_name(u));
}

static int
property_get_current_memory(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error)
{
	Unit *u = userdata;
	uint64_t sz = (uint64_t)-1;
	int r;

	assert(bus);
	assert(reply);
	assert(u);

	if (u->cgroup_path && (u->cgroup_realized_mask & CGROUP_MASK_MEMORY)) {
		_cleanup_free_ char *v = NULL;

		r = cg_get_attribute("memory", u->cgroup_path,
			"memory.usage_in_bytes", &v);
		if (r < 0 && r != -ENOENT)
			log_unit_warning_errno(u->id, r,
				"Couldn't read memory.usage_in_bytes attribute: %m");

		if (v) {
			r = safe_atou64(v, &sz);
			if (r < 0)
				log_unit_warning_errno(u->id, r,
					"Failed to parse memory.usage_in_bytes attribute: %m");
		}
	}

	return sd_bus_message_append(reply, "t", sz);
}

static int
property_get_current_tasks(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	uint64_t cn = (uint64_t)-1;
	Unit *u = userdata;
	int r;

	assert(bus);
	assert(reply);
	assert(u);

	r = unit_get_tasks_current(u, &cn);
	if (r < 0 && r != -ENODATA)
		log_unit_warning_errno(u->id, r,
			"Failed to get pids.current attribute: %m");

	return sd_bus_message_append(reply, "t", cn);
}

const sd_bus_vtable bus_unit_cgroup_vtable[] = { SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("Slice", "s", property_get_slice, 0, 0),
	SD_BUS_PROPERTY("ControlGroup", "s", NULL, offsetof(Unit, cgroup_path),
		0),
	SD_BUS_PROPERTY("MemoryCurrent", "t", property_get_current_memory, 0,
		0),
	SD_BUS_PROPERTY("TasksCurrent", "t", property_get_current_tasks, 0, 0),
	SD_BUS_VTABLE_END };

static int send_new_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        p = unit_dbus_path(u);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        SVC_DBUS_INTERFACE ".Manager",
                        "UnitNew");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "so", u->id, p);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

static int
send_changed_signal(sd_bus *bus, void *userdata)
{
	_cleanup_free_ char *p = NULL;
	Unit *u = userdata;
	int r;

	assert(bus);
	assert(u);

	p = unit_dbus_path(u);
	if (!p)
		return -ENOMEM;

	/* Send a properties changed signal. First for the specific
         * type, then for the generic unit. The clients may rely on
         * this order to get atomic behavior if needed. */

	r = sd_bus_emit_properties_changed_strv(bus, p,
		UNIT_VTABLE(u)->bus_interface, NULL);
	if (r < 0)
		return r;

	return sd_bus_emit_properties_changed_strv(bus, p,
		SVC_DBUS_INTERFACE ".Unit", NULL);
}

void
bus_unit_send_change_signal(Unit *u)
{
	int r;
	assert(u);

	if (u->in_dbus_queue) {
		LIST_REMOVE(dbus_queue, u->manager->dbus_unit_queue, u);
		u->in_dbus_queue = false;
	}

	if (!u->id)
		return;

	r = bus_foreach_bus(u->manager, NULL,
		u->sent_dbus_new_signal ? send_changed_signal : send_new_signal,
		u);
	if (r < 0)
		log_debug_errno(r,
			"Failed to send unit change signal for %s: %m", u->id);

	u->sent_dbus_new_signal = true;
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        p = unit_dbus_path(u);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        SVC_DBUS_INTERFACE ".Manager",
                        "UnitRemoved");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "so", u->id, p);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

void
bus_unit_send_removed_signal(Unit *u)
{
	int r;
	assert(u);

	if (!u->sent_dbus_new_signal)
		bus_unit_send_change_signal(u);

	if (!u->id)
		return;

	r = bus_foreach_bus(u->manager, NULL, send_removed_signal, u);
	if (r < 0)
		log_debug_errno(r,
			"Failed to send unit remove signal for %s: %m", u->id);
}

int bus_unit_queue_job_one(
                sd_bus_message *message,
                Unit *u,
                JobType type,
                JobMode mode,
                BusUnitQueueFlags flags,
                sd_bus_message *reply,
                sd_bus_error *error) {

        _cleanup_set_free_ Set *affected = NULL;
        _cleanup_free_ char *job_path = NULL, *unit_path = NULL;
        Job *j, *a;
        int r;

        if (FLAGS_SET(flags, BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE) && unit_can_reload(u)) {
                if (type == JOB_RESTART)
                        type = JOB_RELOAD_OR_START;
                else if (type == JOB_TRY_RESTART)
                        type = JOB_TRY_RELOAD;
        }

        if (type == JOB_STOP &&
            IN_SET(u->load_state, UNIT_NOT_FOUND, UNIT_ERROR, UNIT_BAD_SETTING) &&
            unit_active_state(u) == UNIT_INACTIVE)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", u->id);

        if ((type == JOB_START && u->refuse_manual_start) ||
            (type == JOB_STOP && u->refuse_manual_stop) ||
            (IN_SET(type, JOB_RESTART, JOB_TRY_RESTART) && (u->refuse_manual_start || u->refuse_manual_stop)) ||
            (type == JOB_RELOAD_OR_START && job_type_collapse(type, u) == JOB_START && u->refuse_manual_start))
                return sd_bus_error_setf(error,
                                         BUS_ERROR_ONLY_BY_DEPENDENCY,
                                         "Operation refused, unit %s may be requested by dependency only (it is configured to refuse manual start/stop).",
                                         u->id);

        /* dbus-broker issues StartUnit for activation requests, and Type=dbus services automatically
         * gain dependency on dbus.socket. Therefore, if dbus has a pending stop job, the new start
         * job that pulls in dbus again would cause job type conflict. Let's avoid that by rejecting
         * job enqueuing early.
         *
         * Note that unlike signal_activation_request(), we can't use unit_inactive_or_pending()
         * here. StartUnit is a more generic interface, and thus users are allowed to use e.g. systemctl
         * to start Type=dbus services even when dbus is inactive. */
        if (type == JOB_START && u->type == UNIT_SERVICE && SERVICE(u)->type == SERVICE_DBUS)
                FOREACH_STRING(dbus_unit, SPECIAL_DBUS_SOCKET, SPECIAL_DBUS_SERVICE) {
                        Unit *dbus;

                        dbus = manager_get_unit(u->manager, dbus_unit);
                        if (dbus && unit_stop_pending(dbus))
                                return sd_bus_error_setf(error,
                                                         BUS_ERROR_SHUTTING_DOWN,
                                                         "Operation for unit %s refused, D-Bus is shutting down.",
                                                         u->id);
                }

        if (FLAGS_SET(flags, BUS_UNIT_QUEUE_VERBOSE_REPLY)) {
                affected = set_new(NULL);
                if (!affected)
                        return -ENOMEM;
        }

        r = manager_add_job(u->manager, type, u, mode, affected, error, &j);
        if (r < 0)
                return r;

        r = bus_job_track_sender(j, message);
        if (r < 0)
                return r;

        /* Before we send the method reply, force out the announcement JobNew for this job */
        bus_job_send_pending_change_signal(j, true);

        job_path = job_dbus_path(j);
        if (!job_path)
                return -ENOMEM;

        /* The classic response is just a job object path */
        if (!FLAGS_SET(flags, BUS_UNIT_QUEUE_VERBOSE_REPLY))
                return sd_bus_message_append(reply, "o", job_path);

        /* In verbose mode respond with the anchor job plus everything that has been affected */

        unit_path = unit_dbus_path(j->unit);
        if (!unit_path)
                return -ENOMEM;

        r = sd_bus_message_append(reply, "uosos",
                                  j->id, job_path,
                                  j->unit->id, unit_path,
                                  job_type_to_string(j->type));
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(uosos)");
        if (r < 0)
                return r;

        SET_FOREACH(a, affected) {
                if (a->id == j->id)
                        continue;

                /* Free paths from previous iteration */
                job_path = mfree(job_path);
                unit_path = mfree(unit_path);

                job_path = job_dbus_path(a);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(a->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(uosos)",
                                          a->id, job_path,
                                          a->unit->id, unit_path,
                                          job_type_to_string(a->type));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

int bus_unit_queue_job(
                sd_bus_message *message,
                Unit *u,
                JobType type,
                JobMode mode,
                BusUnitQueueFlags flags,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(message);
        assert(u);
        assert(type >= 0 && type < _JOB_TYPE_MAX);
        assert(mode >= 0 && mode < _JOB_MODE_MAX);

        r = mac_selinux_unit_access_check(
                        u, message,
                        job_type_to_access_method(type),
                        error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = bus_unit_queue_job_one(message, u, type, mode, flags, reply, error);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int
bus_unit_set_transient_property(Unit *u, const char *name,
	sd_bus_message *message, UnitSetPropertiesMode mode,
	sd_bus_error *error)
{
	int r;

	assert(u);
	assert(name);
	assert(message);

	if (streq(name, "Description")) {
		const char *d;

		r = sd_bus_message_read(message, "s", &d);
		if (r < 0)
			return r;

		if (mode != UNIT_CHECK) {
			r = unit_set_description(u, d);
			if (r < 0)
				return r;

			unit_write_drop_in_format(u, mode, name,
				"[Unit]\nDescription=%s\n", d);
		}

		return 1;

	} else if (streq(name, "DefaultDependencies")) {
		int b;

		r = sd_bus_message_read(message, "b", &b);
		if (r < 0)
			return r;

		if (mode != UNIT_CHECK) {
			u->default_dependencies = b;
			unit_write_drop_in_format(u, mode, name,
				"[Unit]\nDefaultDependencies=%s\n", yes_no(b));
		}

		return 1;

	} else if (streq(name, "CollectMode")) {
		const char *s;
		CollectMode m;

		r = sd_bus_message_read(message, "s", &s);
		if (r < 0)
			return r;

		m = collect_mode_from_string(s);
		if (m < 0)
			return sd_bus_error_setf(error,
				SD_BUS_ERROR_INVALID_ARGS,
				"Unknown garbage collection mode: %s", s);

		if (mode != UNIT_CHECK) {
			u->collect_mode = m;
			unit_write_drop_in_format(u, mode, name,
				"[Unit]\nCollectMode=%s",
				collect_mode_to_string(m));
		}

		return 1;
	} else if (streq(name, "Slice") && unit_get_cgroup_context(u)) {
		const char *s;

		r = sd_bus_message_read(message, "s", &s);
		if (r < 0)
			return r;

		if (!unit_name_is_valid(s, UNIT_NAME_PLAIN) ||
			!endswith(s, ".slice"))
			return sd_bus_error_setf(error,
				SD_BUS_ERROR_INVALID_ARGS,
				"Invalid slice name %s", s);

		if (isempty(s)) {
			if (mode != UNIT_CHECK) {
				unit_ref_unset(&u->slice);
				unit_remove_drop_in(u, mode, name);
			}
		} else {
			Unit *slice;

			/* Note that we do not dispatch the load queue here yet, as we don't want our own transient unit to be
                         * loaded while we are still setting it up. Or in other words, we use manager_load_unit_prepare()
                         * instead of manager_load_unit() on purpose, here. */
			r = manager_load_unit_prepare(u->manager, s, NULL,
				error, &slice);
			if (r < 0)
				return r;

			if (slice->type != UNIT_SLICE)
				return -EINVAL;

			if (mode != UNIT_CHECK) {
				unit_ref_set(&u->slice, u, slice);
				unit_write_drop_in_private_format(u, mode, name,
					"Slice=%s\n", s);
			}
		}

		return 1;
	} else if (STR_IN_SET(name, "Requires", "RequiresOverridable",
			   "Requisite", "RequisiteOverridable", "Wants",
			   "BindsTo", "Conflicts", "Before", "After",
			   "OnFailure", "PropagatesReloadTo",
			   "ReloadPropagatedFrom", "PartOf")) {
		UnitDependency d;
		const char *other;

		d = unit_dependency_from_string(name);
		if (d < 0)
			return -EINVAL;

		r = sd_bus_message_enter_container(message, 'a', "s");
		if (r < 0)
			return r;

		while ((r = sd_bus_message_read(message, "s", &other)) > 0) {
			if (!unit_name_is_valid(other,
				    UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE))
				return sd_bus_error_setf(error,
					SD_BUS_ERROR_INVALID_ARGS,
					"Invalid unit name %s", other);

			if (mode != UNIT_CHECK) {
				_cleanup_free_ char *label = NULL;

				r = unit_add_dependency_by_name(u, d, other,
					NULL, true);
				if (r < 0)
					return r;

				label = strjoin(name, "-", other, NULL);
				if (!label)
					return -ENOMEM;

				unit_write_drop_in_format(u, mode, label,
					"[Unit]\n%s=%s\n", name, other);
			}
		}
		if (r < 0)
			return r;

		r = sd_bus_message_exit_container(message);
		if (r < 0)
			return r;

		return 1;
	}

	return 0;
}

int
bus_unit_set_properties(Unit *u, sd_bus_message *message,
	UnitSetPropertiesMode mode, bool commit, sd_bus_error *error)
{
	bool for_real = false;
	unsigned n = 0;
	int r;

	assert(u);
	assert(message);

	/* We iterate through the array twice. First run we just check
         * if all passed data is valid, second run actually applies
         * it. This is to implement transaction-like behaviour without
         * actually providing full transactions. */

	r = sd_bus_message_enter_container(message, 'a', "(sv)");
	if (r < 0)
		return r;

	for (;;) {
		const char *name;

		r = sd_bus_message_enter_container(message, 'r', "sv");
		if (r < 0)
			return r;
		if (r == 0) {
			if (for_real || mode == UNIT_CHECK)
				break;

			/* Reached EOF. Let's try again, and this time for realz... */
			r = sd_bus_message_rewind(message, false);
			if (r < 0)
				return r;

			for_real = true;
			continue;
		}

		r = sd_bus_message_read(message, "s", &name);
		if (r < 0)
			return r;

		if (!UNIT_VTABLE(u)->bus_set_property)
			return sd_bus_error_setf(error,
				SD_BUS_ERROR_PROPERTY_READ_ONLY,
				"Objects of this type do not support setting properties.");

		r = sd_bus_message_enter_container(message, 'v', NULL);
		if (r < 0)
			return r;

		r = UNIT_VTABLE(u)->bus_set_property(u, name, message,
			for_real ? mode : UNIT_CHECK, error);
		if (r == 0 && u->transient && u->load_state == UNIT_STUB)
			r = bus_unit_set_transient_property(u, name, message,
				for_real ? mode : UNIT_CHECK, error);
		if (r < 0)
			return r;
		if (r == 0)
			return sd_bus_error_setf(error,
				SD_BUS_ERROR_PROPERTY_READ_ONLY,
				"Cannot set property %s, or unknown property.",
				name);

		r = sd_bus_message_exit_container(message);
		if (r < 0)
			return r;

		r = sd_bus_message_exit_container(message);
		if (r < 0)
			return r;

		n += for_real;
	}

	r = sd_bus_message_exit_container(message);
	if (r < 0)
		return r;

	if (commit && n > 0 && UNIT_VTABLE(u)->bus_commit_properties)
		UNIT_VTABLE(u)->bus_commit_properties(u);

	return n;
}

int
bus_unit_check_load_state(Unit *u, sd_bus_error *error)
{
	if (u->load_state == UNIT_LOADED)
		return 0;

	/* Give a better description of the unit error when
         * possible. Note that in the case of UNIT_MASKED, load_error
         * is not set. */
	if (u->load_state == UNIT_MASKED)
		return sd_bus_error_setf(error, BUS_ERROR_UNIT_MASKED,
			"Unit is masked.");

	if (u->load_state == UNIT_NOT_FOUND)
		return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT,
			"Unit not found.");

	return sd_bus_error_set_errnof(error, u->load_error,
		"Unit is not loaded properly: %m.");
}
