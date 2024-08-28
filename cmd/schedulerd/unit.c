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

#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bsdsignal.h"
#include "bus-common-errors.h"
#include "cgroup-util.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "dropin.h"
#include "execute.h"
#include "fileio-label.h"
#include "label.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "path-util.h"
#include "sd-id128.h"
#include "sd-messages.h"
#include "set.h"
#include "special.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"
#include "virt.h"

const UnitVTable *const unit_vtable[_UNIT_TYPE_MAX] = {
	[UNIT_SERVICE] = &service_vtable,
	[UNIT_SOCKET] = &socket_vtable,
	[UNIT_TARGET] = &target_vtable,
	[UNIT_SNAPSHOT] = &snapshot_vtable,
	[UNIT_TIMER] = &timer_vtable,
	[UNIT_PATH] = &path_vtable,
	[UNIT_SLICE] = &slice_vtable,
	[UNIT_SCOPE] = &scope_vtable,
#ifdef SVC_USE_Device
	[UNIT_DEVICE] = &device_vtable,
#endif
#ifdef SVC_USE_Automount
	[UNIT_MOUNT] = &mount_vtable,
	[UNIT_AUTOMOUNT] = &automount_vtable,
#endif
#ifdef SVC_USE_Swap
	[UNIT_SWAP] = &swap_vtable,
#endif
};

static int maybe_warn_about_dependency(const char *id, const char *other,
	UnitDependency dependency);

Unit *
unit_new(Manager *m, size_t size)
{
	Unit *u;

	assert(m);
	assert(size >= sizeof(Unit));

	u = malloc0(size);
	if (!u)
		return NULL;

	u->names = set_new(&string_hash_ops);
	if (!u->names) {
		free(u);
		return NULL;
	}

	u->manager = m;
	u->type = _UNIT_TYPE_INVALID;
	u->deserialized_job = _JOB_TYPE_INVALID;
	u->default_dependencies = true;
	u->unit_file_state = _UNIT_FILE_STATE_INVALID;
	u->unit_file_preset = -1;
	u->on_failure_job_mode = JOB_REPLACE;
	u->sigchldgen = 0;

	RATELIMIT_INIT(u->check_unneeded_ratelimit, 10 * USEC_PER_SEC, 16);

	return u;
}

bool
unit_has_name(Unit *u, const char *name)
{
	assert(u);
	assert(name);

	return !!set_get(u->names, (char *)name);
}

static void
unit_init(Unit *u)
{
	CGroupContext *cc;
	ExecContext *ec;
	KillContext *kc;

	assert(u);
	assert(u->manager);
	assert(u->type >= 0);

	cc = unit_get_cgroup_context(u);
	if (cc) {
		cgroup_context_init(cc);

		/* Copy in the manager defaults into the cgroup
                 * context, _before_ the rest of the settings have
                 * been initialized */

		cc->cpu_accounting = u->manager->default_cpu_accounting;
		cc->blockio_accounting = u->manager->default_blockio_accounting;
		cc->memory_accounting = u->manager->default_memory_accounting;
		cc->tasks_accounting = u->manager->default_tasks_accounting;

		if (u->type != UNIT_SLICE)
			cc->tasks_max = u->manager->default_tasks_max;
	}

	ec = unit_get_exec_context(u);
	if (ec)
		exec_context_init(ec);

	kc = unit_get_kill_context(u);
	if (kc)
		kill_context_init(kc);

	if (UNIT_VTABLE(u)->init)
		UNIT_VTABLE(u)->init(u);
}

int
unit_add_name(Unit *u, const char *text)
{
	_cleanup_free_ char *s = NULL, *i = NULL;
	UnitType t;
	int r;

	assert(u);
	assert(text);

	if (unit_name_is_template(text)) {
		if (!u->instance)
			return -EINVAL;

		s = unit_name_replace_instance(text, u->instance);
	} else
		s = strdup(text);
	if (!s)
		return -ENOMEM;

	if (!unit_name_is_valid(s, UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE))
		return -EINVAL;

	assert_se((t = unit_name_to_type(s)) >= 0);

	if (u->type != _UNIT_TYPE_INVALID && t != u->type)
		return -EINVAL;

	r = unit_name_to_instance(s, &i);
	if (r < 0)
		return r;

	if (i && unit_vtable[t]->no_instances)
		return -EINVAL;

	/* Ensure that this unit is either instanced or not instanced,
         * but not both. */
	if (u->type != _UNIT_TYPE_INVALID && !u->instance != !i)
		return -EINVAL;

	if (unit_vtable[t]->no_alias && !set_isempty(u->names) &&
		!set_get(u->names, s))
		return -EEXIST;

	if (hashmap_size(u->manager->units) >= MANAGER_MAX_NAMES)
		return -E2BIG;

	r = set_put(u->names, s);
	if (r < 0) {
		if (r == -EEXIST)
			return 0;

		return r;
	}

	r = hashmap_put(u->manager->units, s, u);
	if (r < 0) {
		set_remove(u->names, s);
		return r;
	}

	if (u->type == _UNIT_TYPE_INVALID) {
		u->type = t;
		u->id = s;
		u->instance = i;

		IWLIST_PREPEND(units_by_type, u->manager->units_by_type[t], u);

		unit_init(u);

		i = NULL;
	}

	s = NULL;

	unit_add_to_dbus_queue(u);
	return 0;
}

int
unit_choose_id(Unit *u, const char *name)
{
	_cleanup_free_ char *t = NULL;
	char *s, *i;
	int r;

	assert(u);
	assert(name);

	if (unit_name_is_template(name)) {
		if (!u->instance)
			return -EINVAL;

		t = unit_name_replace_instance(name, u->instance);
		if (!t)
			return -ENOMEM;

		name = t;
	}

	/* Selects one of the names of this unit as the id */
	s = set_get(u->names, (char *)name);
	if (!s)
		return -ENOENT;

	r = unit_name_to_instance(s, &i);
	if (r < 0)
		return r;

	u->id = s;

	free(u->instance);
	u->instance = i;

	unit_add_to_dbus_queue(u);

	return 0;
}

int
unit_set_description(Unit *u, const char *description)
{
	char *s;

	assert(u);

	if (isempty(description))
		s = NULL;
	else {
		if (streq_ptr(u->description, description))
			return 0;

		s = strdup(description);
		if (!s)
			return -ENOMEM;
	}

	free(u->description);
	u->description = s;

	unit_add_to_dbus_queue(u);
	return 0;
}

bool
unit_may_gc(Unit *u)
{
	UnitActiveState state;

	assert(u);

	/* Checks whether the unit is ready to be unloaded for garbage collection.
         * Returns true when the unit may be collected, and false if there's some
         * reason to keep it loaded.
         *
         * References from other units are *not* checked here. Instead, this is done
         * in unit_gc_sweep(), but using markers to properly collect dependency loops.
         */

	if (u->job)
		return false;

	if (u->nop_job)
		return false;

	state = unit_active_state(u);

	/* If the unit is inactive and failed and no job is queued for it, then release its runtime resources */
	if (UNIT_IS_INACTIVE_OR_FAILED(state) &&
		UNIT_VTABLE(u)->release_resources)
		UNIT_VTABLE(u)->release_resources(u);

	if (UNIT_VTABLE(u)->no_gc)
		return false;

	if (u->no_gc)
		return false;

	/* But we keep the unit object around for longer when it is referenced or configured to not be gc'ed */
	switch (u->collect_mode) {
	case COLLECT_INACTIVE:
		if (state != UNIT_INACTIVE)
			return false;

		break;

	case COLLECT_INACTIVE_OR_FAILED:
		if (!IN_SET(state, UNIT_INACTIVE, UNIT_FAILED))
			return false;

		break;

	default:
		assert_not_reached();
	}

	if (UNIT_VTABLE(u)->may_gc && !UNIT_VTABLE(u)->may_gc(u))
		return false;

	return true;
}

void
unit_add_to_load_queue(Unit *u)
{
	assert(u);
	assert(u->type != _UNIT_TYPE_INVALID);

	if (u->load_state != UNIT_STUB || u->in_load_queue)
		return;

	IWLIST_PREPEND(load_queue, u->manager->load_queue, u);
	u->in_load_queue = true;
}

void
unit_add_to_cleanup_queue(Unit *u)
{
	assert(u);

	if (u->in_cleanup_queue)
		return;

	IWLIST_PREPEND(cleanup_queue, u->manager->cleanup_queue, u);
	u->in_cleanup_queue = true;
}

void
unit_add_to_gc_queue(Unit *u)
{
	assert(u);

	if (u->in_gc_queue || u->in_cleanup_queue)
		return;

	if (!unit_may_gc(u))
		return;

	IWLIST_PREPEND(gc_queue, u->manager->gc_queue, u);
	u->in_gc_queue = true;

	u->manager->n_in_gc_queue++;
}

void
unit_add_to_dbus_queue(Unit *u)
{
	assert(u);
	assert(u->type != _UNIT_TYPE_INVALID);

	if (u->load_state == UNIT_STUB || u->in_dbus_queue)
		return;

	/* Shortcut things if nobody cares */
	if (sd_bus_track_count(u->manager->subscribed) <= 0 &&
		set_isempty(u->manager->private_buses)) {
		u->sent_dbus_new_signal = true;
		return;
	}

	IWLIST_PREPEND(dbus_queue, u->manager->dbus_unit_queue, u);
	u->in_dbus_queue = true;
}

void
unit_add_to_stop_when_unneeded_queue(Unit *u)
{
	assert(u);

	if (u->in_stop_when_unneeded_queue)
		return;

	if (!u->stop_when_unneeded)
		return;

	if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
		return;

	IWLIST_PREPEND(stop_when_unneeded_queue,
		u->manager->stop_when_unneeded_queue, u);
	u->in_stop_when_unneeded_queue = true;
}

static void
bidi_set_free(Unit *u, Set *s)
{
	Iterator i;
	Unit *other;

	assert(u);

	/* Frees the set and makes sure we are dropped from the
         * inverse pointers */

	SET_FOREACH (other, s, i) {
		UnitDependency d;

		for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
			set_remove(other->dependencies[d], u);

		unit_add_to_gc_queue(other);
	}

	set_free(s);
}

static void
unit_remove_transient(Unit *u)
{
	char **i;

	assert(u);

	if (!u->transient)
		return;

	if (u->fragment_path)
		unlink(u->fragment_path);

	STRV_FOREACH (i, u->dropin_paths) {
		_cleanup_free_ char *p = NULL;
		int r;

		unlink(*i);

		r = path_get_parent(*i, &p);
		if (r >= 0)
			rmdir(p);
	}
}

static void
unit_free_requires_mounts_for(Unit *u)
{
	char **j;

	STRV_FOREACH (j, u->requires_mounts_for) {
		char s[strlen(*j) + 1];

		PATH_FOREACH_PREFIX_MORE (s, *j) {
			char *y;
			Set *x;

			x = hashmap_get2(u->manager->units_requiring_mounts_for,
				s, (void **)&y);
			if (!x)
				continue;

			set_remove(x, u);

			if (set_isempty(x)) {
				hashmap_remove(
					u->manager->units_requiring_mounts_for,
					y);
				free(y);
				set_free(x);
			}
		}
	}

	strv_free(u->requires_mounts_for);
	u->requires_mounts_for = NULL;
}

static void
unit_done(Unit *u)
{
	ExecContext *ec;
	CGroupContext *cc;

	assert(u);

	if (u->type < 0)
		return;

	if (UNIT_VTABLE(u)->done)
		UNIT_VTABLE(u)->done(u);

	ec = unit_get_exec_context(u);
	if (ec)
		exec_context_done(ec);

	cc = unit_get_cgroup_context(u);
	if (cc)
		cgroup_context_done(cc);
}

void
unit_free(Unit *u)
{
	UnitDependency d;
	Iterator i;
	char *t;

	assert(u);

	if (u->manager->n_reloading <= 0)
		unit_remove_transient(u);

	bus_unit_send_removed_signal(u);

	unit_done(u);

	unit_free_requires_mounts_for(u);

	SET_FOREACH (t, u->names, i)
		hashmap_remove_value(u->manager->units, t, u);

	if (u->job) {
		Job *j = u->job;
		job_uninstall(j);
		job_free(j);
	}

	if (u->nop_job) {
		Job *j = u->nop_job;
		job_uninstall(j);
		job_free(j);
	}

	for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
		bidi_set_free(u, u->dependencies[d]);

	if (u->in_target_deps_queue)
		IWLIST_REMOVE(target_deps_queue, u->manager->target_deps_queue,
			u);

	if (u->in_cgroup_queue)
		IWLIST_REMOVE(cgroup_queue, u->manager->cgroup_queue, u);

	if (u->cgroup_path) {
		hashmap_remove(u->manager->cgroup_unit, u->cgroup_path);
		u->cgroup_path = mfree(u->cgroup_path);
	}

	set_remove(u->manager->failed_units, u);
	set_remove(u->manager->startup_units, u);

	unit_unwatch_all_pids(u);

	unit_ref_unset(&u->slice);
	while (u->refs_by_target)
		unit_ref_unset(u->refs_by_target);

	if (u->type != _UNIT_TYPE_INVALID)
		IWLIST_REMOVE(units_by_type, u->manager->units_by_type[u->type],
			u);

	if (u->in_load_queue)
		IWLIST_REMOVE(load_queue, u->manager->load_queue, u);

	if (u->in_dbus_queue)
		IWLIST_REMOVE(dbus_queue, u->manager->dbus_unit_queue, u);

	if (u->in_cleanup_queue)
		IWLIST_REMOVE(cleanup_queue, u->manager->cleanup_queue, u);

	if (u->in_gc_queue) {
		IWLIST_REMOVE(gc_queue, u->manager->gc_queue, u);
		u->manager->n_in_gc_queue--;
	}

	if (u->in_stop_when_unneeded_queue)
		IWLIST_REMOVE(stop_when_unneeded_queue,
			u->manager->stop_when_unneeded_queue, u);

	if (u->on_console)
		manager_unref_console(u->manager);

	condition_free_list(u->conditions);
	condition_free_list(u->asserts);

	free(u->description);
	strv_free(u->documentation);
	free(u->fragment_path);
	free(u->source_path);
	strv_free(u->dropin_paths);
	free(u->instance);

	free(u->job_timeout_reboot_arg);

	set_free_free(u->names);

	free(u);
}

UnitActiveState
unit_active_state(Unit *u)
{
	assert(u);

	if (u->load_state == UNIT_MERGED)
		return unit_active_state(unit_follow_merge(u));

	/* After a reload it might happen that a unit is not correctly
         * loaded but still has a process around. That's why we won't
         * shortcut failed loading to UNIT_INACTIVE_FAILED. */

	return UNIT_VTABLE(u)->active_state(u);
}

const char *
unit_sub_state_to_string(Unit *u)
{
	assert(u);

	return UNIT_VTABLE(u)->sub_state_to_string(u);
}

static int
complete_move(Set **s, Set **other)
{
	int r;

	assert(s);
	assert(other);

	if (!*other)
		return 0;

	if (*s) {
		r = set_move(*s, *other);
		if (r < 0)
			return r;
	} else {
		*s = *other;
		*other = NULL;
	}

	return 0;
}

static int
merge_names(Unit *u, Unit *other)
{
	char *t;
	Iterator i;
	int r;

	assert(u);
	assert(other);

	r = complete_move(&u->names, &other->names);
	if (r < 0)
		return r;

	set_free_free(other->names);
	other->names = NULL;
	other->id = NULL;

	SET_FOREACH (t, u->names, i)
		assert_se(hashmap_replace(u->manager->units, t, u) == 0);

	return 0;
}

static int
reserve_dependencies(Unit *u, Unit *other, UnitDependency d)
{
	unsigned n_reserve;

	assert(u);
	assert(other);
	assert(d < _UNIT_DEPENDENCY_MAX);

	/*
         * If u does not have this dependency set allocated, there is no need
         * to reserve anything. In that case other's set will be transferred
         * as a whole to u by complete_move().
         */
	if (!u->dependencies[d])
		return 0;

	/* merge_dependencies() will skip a u-on-u dependency */
	n_reserve = set_size(other->dependencies[d]) -
		!!set_get(other->dependencies[d], u);

	return set_reserve(u->dependencies[d], n_reserve);
}

static void
merge_dependencies(Unit *u, Unit *other, const char *other_id, UnitDependency d)
{
	Iterator i;
	Unit *back;
	int r;

	assert(u);
	assert(other);
	assert(d < _UNIT_DEPENDENCY_MAX);

	/* Fix backwards pointers */
	SET_FOREACH (back, other->dependencies[d], i) {
		UnitDependency k;

		for (k = 0; k < _UNIT_DEPENDENCY_MAX; k++) {
			/* Do not add dependencies between u and itself */
			if (back == u) {
				if (set_remove(back->dependencies[k], other))
					maybe_warn_about_dependency(u->id,
						other_id, k);
			} else {
				r = set_remove_and_put(back->dependencies[k],
					other, u);
				if (r == -EEXIST)
					set_remove(back->dependencies[k],
						other);
				else
					assert(r >= 0 || r == -ENOENT);
			}
		}
	}

	/* Also do not move dependencies on u to itself */
	back = set_remove(other->dependencies[d], u);
	if (back)
		maybe_warn_about_dependency(u->id, other_id, d);

	/* The move cannot fail. The caller must have performed a reservation. */
	assert_se(complete_move(&u->dependencies[d], &other->dependencies[d]) ==
		0);

	set_free(other->dependencies[d]);
	other->dependencies[d] = NULL;
}

int
unit_merge(Unit *u, Unit *other)
{
	UnitDependency d;
	const char *other_id = NULL;
	int r;

	assert(u);
	assert(other);
	assert(u->manager == other->manager);
	assert(u->type != _UNIT_TYPE_INVALID);

	other = unit_follow_merge(other);

	if (other == u)
		return 0;

	if (u->type != other->type)
		return -EINVAL;

	if (!u->instance != !other->instance)
		return -EINVAL;

	if (other->load_state != UNIT_STUB &&
		other->load_state != UNIT_NOT_FOUND)
		return -EEXIST;

	if (other->job)
		return -EEXIST;

	if (other->nop_job)
		return -EEXIST;

	if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other)))
		return -EEXIST;

	if (other->id)
		other_id = strdupa(other->id);

	/* Make reservations to ensure merge_dependencies() won't fail */
	for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
		r = reserve_dependencies(u, other, d);
		/*
                 * We don't rollback reservations if we fail. We don't have
                 * a way to undo reservations. A reservation is not a leak.
                 */
		if (r < 0)
			return r;
	}

	/* Merge names */
	r = merge_names(u, other);
	if (r < 0)
		return r;

	/* Redirect all references */
	while (other->refs_by_target)
		unit_ref_set(other->refs_by_target,
			other->refs_by_target->source, u);

	/* Merge dependencies */
	for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
		merge_dependencies(u, other, other_id, d);

	other->load_state = UNIT_MERGED;
	other->merged_into = u;

	/* If there is still some data attached to the other node, we
         * don't need it anymore, and can free it. */
	if (other->load_state != UNIT_STUB)
		if (UNIT_VTABLE(other)->done)
			UNIT_VTABLE(other)->done(other);

	unit_add_to_dbus_queue(u);
	unit_add_to_cleanup_queue(other);

	return 0;
}

int
unit_merge_by_name(Unit *u, const char *name)
{
	Unit *other;
	int r;
	_cleanup_free_ char *s = NULL;

	assert(u);
	assert(name);

	if (unit_name_is_template(name)) {
		if (!u->instance)
			return -EINVAL;

		s = unit_name_replace_instance(name, u->instance);
		if (!s)
			return -ENOMEM;

		name = s;
	}

	other = manager_get_unit(u->manager, name);
	if (!other)
		r = unit_add_name(u, name);
	else
		r = unit_merge(u, other);

	return r;
}

Unit *
unit_follow_merge(Unit *u)
{
	assert(u);

	while (u->load_state == UNIT_MERGED)
		assert_se(u = u->merged_into);

	return u;
}

int
unit_add_exec_dependencies(Unit *u, ExecContext *c)
{
	int r;

	assert(u);
	assert(c);

	if (c->working_directory) {
		r = unit_require_mounts_for(u, c->working_directory);
		if (r < 0)
			return r;
	}

	if (c->root_directory) {
		r = unit_require_mounts_for(u, c->root_directory);
		if (r < 0)
			return r;
	}

	if (u->manager->running_as != SYSTEMD_SYSTEM)
		return 0;

	if (c->private_tmp) {
		r = unit_add_dependency_by_name(u, UNIT_AFTER, "tmp.mount",
			NULL, true);
		if (r < 0)
			return r;

		r = unit_require_mounts_for(u, "/var/tmp");
		if (r < 0)
			return r;
	}

	if (c->std_output != EXEC_OUTPUT_KMSG &&
		c->std_output != EXEC_OUTPUT_SYSLOG &&
		c->std_output != EXEC_OUTPUT_JOURNAL &&
		c->std_output != EXEC_OUTPUT_KMSG_AND_CONSOLE &&
		c->std_output != EXEC_OUTPUT_SYSLOG_AND_CONSOLE &&
		c->std_output != EXEC_OUTPUT_JOURNAL_AND_CONSOLE &&
		c->std_error != EXEC_OUTPUT_KMSG &&
		c->std_error != EXEC_OUTPUT_SYSLOG &&
		c->std_error != EXEC_OUTPUT_JOURNAL &&
		c->std_error != EXEC_OUTPUT_KMSG_AND_CONSOLE &&
		c->std_error != EXEC_OUTPUT_JOURNAL_AND_CONSOLE &&
		c->std_error != EXEC_OUTPUT_SYSLOG_AND_CONSOLE)
		return 0;

	/* If syslog or kernel logging is requested, make sure our own
         * logging daemon is run first. */

	r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_JOURNALD_SOCKET,
		NULL, true);
	if (r < 0)
		return r;

	return 0;
}

const char *
unit_description(Unit *u)
{
	assert(u);

	if (u->description)
		return u->description;

	return strna(u->id);
}

void
unit_dump(Unit *u, FILE *f, const char *prefix)
{
	char *t, **j;
	UnitDependency d;
	Iterator i;
	const char *prefix2;
	char timestamp1[FORMAT_TIMESTAMP_MAX], timestamp2[FORMAT_TIMESTAMP_MAX],
		timestamp3[FORMAT_TIMESTAMP_MAX],
		timestamp4[FORMAT_TIMESTAMP_MAX], timespan[FORMAT_TIMESPAN_MAX];
	Unit *following;
	_cleanup_set_free_ Set *following_set = NULL;
	int r;

	assert(u);
	assert(u->type >= 0);

	prefix = strempty(prefix);
	prefix2 = strjoina(prefix, "\t");

	fprintf(f,
		"%s-> Unit %s:\n"
		"%s\tDescription: %s\n"
		"%s\tInstance: %s\n"
		"%s\tUnit Load State: %s\n"
		"%s\tUnit Active State: %s\n"
		"%s\tInactive Exit Timestamp: %s\n"
		"%s\tActive Enter Timestamp: %s\n"
		"%s\tActive Exit Timestamp: %s\n"
		"%s\tInactive Enter Timestamp: %s\n"
		"%s\tMay GC: %s\n"
		"%s\tNeed Daemon Reload: %s\n"
		"%s\tTransient: %s\n"
		"%s\tGarbage Collection Mode: %s\n"
		"%s\tSlice: %s\n"
		"%s\tCGroup: %s\n"
		"%s\tCGroup realized: %s\n"
		"%s\tCGroup mask: 0x%x\n"
		"%s\tCGroup members mask: 0x%x\n",
		prefix, u->id, prefix, unit_description(u), prefix,
		strna(u->instance), prefix,
		unit_load_state_to_string(u->load_state), prefix,
		unit_active_state_to_string(unit_active_state(u)), prefix,
		strna(format_timestamp(timestamp1, sizeof(timestamp1),
			u->inactive_exit_timestamp.realtime)),
		prefix,
		strna(format_timestamp(timestamp2, sizeof(timestamp2),
			u->active_enter_timestamp.realtime)),
		prefix,
		strna(format_timestamp(timestamp3, sizeof(timestamp3),
			u->active_exit_timestamp.realtime)),
		prefix,
		strna(format_timestamp(timestamp4, sizeof(timestamp4),
			u->inactive_enter_timestamp.realtime)),
		prefix, yes_no(unit_may_gc(u)), prefix,
		yes_no(unit_need_daemon_reload(u)), prefix,
		yes_no(u->transient), prefix,
		collect_mode_to_string(u->collect_mode), prefix,
		strna(unit_slice_name(u)), prefix, strna(u->cgroup_path),
		prefix, yes_no(u->cgroup_realized), prefix,
		u->cgroup_realized_mask, prefix, u->cgroup_members_mask);

	SET_FOREACH (t, u->names, i)
		fprintf(f, "%s\tName: %s\n", prefix, t);

	STRV_FOREACH (j, u->documentation)
		fprintf(f, "%s\tDocumentation: %s\n", prefix, *j);

	following = unit_following(u);
	if (following)
		fprintf(f, "%s\tFollowing: %s\n", prefix, following->id);

	r = unit_following_set(u, &following_set);
	if (r >= 0) {
		Unit *other;

		SET_FOREACH (other, following_set, i)
			fprintf(f, "%s\tFollowing Set Member: %s\n", prefix,
				other->id);
	}

	if (u->fragment_path)
		fprintf(f, "%s\tFragment Path: %s\n", prefix, u->fragment_path);

	if (u->source_path)
		fprintf(f, "%s\tSource Path: %s\n", prefix, u->source_path);

	STRV_FOREACH (j, u->dropin_paths)
		fprintf(f, "%s\tDropIn Path: %s\n", prefix, *j);

	if (u->job_timeout > 0)
		fprintf(f, "%s\tJob Timeout: %s\n", prefix,
			format_timespan(timespan, sizeof(timespan),
				u->job_timeout, 0));

	if (u->job_timeout_action != EMERGENCY_ACTION_NONE)
		fprintf(f, "%s\tJob Timeout Action: %s\n", prefix,
			emergency_action_to_string(u->job_timeout_action));

	if (u->job_timeout_reboot_arg)
		fprintf(f, "%s\tJob Timeout Reboot Argument: %s\n", prefix,
			u->job_timeout_reboot_arg);

	condition_dump_list(u->conditions, f, prefix, condition_type_to_string);
	condition_dump_list(u->asserts, f, prefix, assert_type_to_string);

	if (dual_timestamp_is_set(&u->condition_timestamp))
		fprintf(f,
			"%s\tCondition Timestamp: %s\n"
			"%s\tCondition Result: %s\n",
			prefix,
			strna(format_timestamp(timestamp1, sizeof(timestamp1),
				u->condition_timestamp.realtime)),
			prefix, yes_no(u->condition_result));

	if (dual_timestamp_is_set(&u->assert_timestamp))
		fprintf(f,
			"%s\tAssert Timestamp: %s\n"
			"%s\tAssert Result: %s\n",
			prefix,
			strna(format_timestamp(timestamp1, sizeof(timestamp1),
				u->assert_timestamp.realtime)),
			prefix, yes_no(u->assert_result));

	for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
		Unit *other;

		SET_FOREACH (other, u->dependencies[d], i)
			fprintf(f, "%s\t%s: %s\n", prefix,
				unit_dependency_to_string(d), other->id);
	}

	if (!strv_isempty(u->requires_mounts_for)) {
		fprintf(f, "%s\tRequiresMountsFor:", prefix);

		STRV_FOREACH (j, u->requires_mounts_for)
			fprintf(f, " %s", *j);

		fputs("\n", f);
	}

	if (u->load_state == UNIT_LOADED) {
		fprintf(f,
			"%s\tStopWhenUnneeded: %s\n"
			"%s\tRefuseManualStart: %s\n"
			"%s\tRefuseManualStop: %s\n"
			"%s\tDefaultDependencies: %s\n"
			"%s\tOnFailureJobMode: %s\n"
			"%s\tIgnoreOnIsolate: %s\n"
			"%s\tIgnoreOnSnapshot: %s\n",
			prefix, yes_no(u->stop_when_unneeded), prefix,
			yes_no(u->refuse_manual_start), prefix,
			yes_no(u->refuse_manual_stop), prefix,
			yes_no(u->default_dependencies), prefix,
			job_mode_to_string(u->on_failure_job_mode), prefix,
			yes_no(u->ignore_on_isolate), prefix,
			yes_no(u->ignore_on_snapshot));

		if (UNIT_VTABLE(u)->dump)
			UNIT_VTABLE(u)->dump(u, f, prefix2);

	} else if (u->load_state == UNIT_MERGED)
		fprintf(f, "%s\tMerged into: %s\n", prefix, u->merged_into->id);
	else if (u->load_state == UNIT_ERROR)
		fprintf(f, "%s\tLoad Error Code: %s\n", prefix,
			strerror(-u->load_error));

	if (u->job)
		job_dump(u->job, f, prefix2);

	if (u->nop_job)
		job_dump(u->nop_job, f, prefix2);
}

/* Common implementation for multiple backends */
int
unit_load_fragment_and_dropin(Unit *u)
{
	int r;

	assert(u);

	/* Load a .{service,socket,...} file */
	r = unit_load_fragment(u);
	if (r < 0)
		return r;

	if (u->load_state == UNIT_STUB)
		return -ENOENT;

	/* Load drop-in directory data */
	r = unit_load_dropin(unit_follow_merge(u));
	if (r < 0)
		return r;

	return 0;
}

/* Common implementation for multiple backends */
int
unit_load_fragment_and_dropin_optional(Unit *u)
{
	int r;

	assert(u);

	/* Same as unit_load_fragment_and_dropin(), but whether
         * something can be loaded or not doesn't matter. */

	/* Load a .service file */
	r = unit_load_fragment(u);
	if (r < 0)
		return r;

	if (u->load_state == UNIT_STUB)
		u->load_state = UNIT_LOADED;

	/* Load drop-in directory data */
	r = unit_load_dropin(unit_follow_merge(u));
	if (r < 0)
		return r;

	return 0;
}

void
unit_add_to_target_deps_queue(Unit *u)
{
	Manager *m = u->manager;

	assert(u);

	if (u->in_target_deps_queue)
		return;

	IWLIST_PREPEND(target_deps_queue, m->target_deps_queue, u);
	u->in_target_deps_queue = true;
}

int
unit_add_default_target_dependency(Unit *u, Unit *target)
{
	assert(u);
	assert(target);

	if (target->type != UNIT_TARGET)
		return 0;

	/* Only add the dependency if both units are loaded, so that
         * that loop check below is reliable */
	if (u->load_state != UNIT_LOADED || target->load_state != UNIT_LOADED)
		return 0;

	/* If either side wants no automatic dependencies, then let's
         * skip this */
	if (!u->default_dependencies || !target->default_dependencies)
		return 0;

	/* Don't create loops */
	if (set_get(target->dependencies[UNIT_BEFORE], u))
		return 0;

	return unit_add_dependency(target, UNIT_AFTER, u, true);
}

static int
unit_add_slice_dependencies(Unit *u)
{
	assert(u);

	if (!unit_get_cgroup_context(u))
		return 0;

	if (UNIT_ISSET(u->slice))
		return unit_add_two_dependencies(u, UNIT_AFTER, UNIT_REQUIRES,
			UNIT_DEREF(u->slice), true);

	if (unit_has_name(u, SPECIAL_ROOT_SLICE))
		return 0;

	return unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES,
		SPECIAL_ROOT_SLICE, NULL, true);
}

static int
unit_add_mount_dependencies(Unit *u)
{
	char **i;
	int r;

	assert(u);

	STRV_FOREACH (i, u->requires_mounts_for) {
		char prefix[strlen(*i) + 1];

		PATH_FOREACH_PREFIX_MORE (prefix, *i) {
			_cleanup_free_ char *p = NULL;
			Unit *m;

			p = unit_name_from_path(prefix, ".mount");
			if (!p)
				return -ENOMEM;

			m = manager_get_unit(u->manager, p);
			if (!m) {
				/* Make sure to load the mount unit if
                                 * it exists. If so the dependencies
                                 * on this unit will be added later
                                 * during the loading of the mount
                                 * unit. */
				(void)manager_load_unit_prepare(u->manager, p,
					NULL, NULL, &m);
				continue;
			}
			if (m == u)
				continue;

			if (m->load_state != UNIT_LOADED)
				continue;

			r = unit_add_dependency(u, UNIT_AFTER, m, true);
			if (r < 0)
				return r;

			if (m->fragment_path && !streq(m->id, "tmp.mount")) {
				r = unit_add_dependency(u, UNIT_REQUIRES, m,
					true);
				if (r < 0)
					return r;
			}
		}
	}

	return 0;
}

static int
unit_add_startup_units(Unit *u)
{
	CGroupContext *c;
	int r = 0;

	c = unit_get_cgroup_context(u);
	if (!c)
		return 0;

	if (c->startup_cpu_shares == CGROUP_CPU_SHARES_INVALID &&
		c->startup_blockio_weight == CGROUP_BLKIO_WEIGHT_INVALID)
		return 0;

	r = set_put(u->manager->startup_units, u);
	if (r == -EEXIST)
		return 0;

	return r;
}

int
unit_load(Unit *u)
{
	int r;

	assert(u);

	if (u->in_load_queue) {
		IWLIST_REMOVE(load_queue, u->manager->load_queue, u);
		u->in_load_queue = false;
	}

	if (u->type == _UNIT_TYPE_INVALID)
		return -EINVAL;

	if (u->load_state != UNIT_STUB)
		return 0;

	if (UNIT_VTABLE(u)->load) {
		r = UNIT_VTABLE(u)->load(u);
		if (r < 0)
			goto fail;
	}

	if (u->load_state == UNIT_STUB) {
		r = -ENOENT;
		goto fail;
	}

	if (u->load_state == UNIT_LOADED) {
		unit_add_to_target_deps_queue(u);

		r = unit_add_slice_dependencies(u);
		if (r < 0)
			goto fail;

		r = unit_add_mount_dependencies(u);
		if (r < 0)
			goto fail;

		r = unit_add_startup_units(u);
		if (r < 0)
			goto fail;

		if (u->on_failure_job_mode == JOB_ISOLATE &&
			set_size(u->dependencies[UNIT_ON_FAILURE]) > 1) {
			log_unit_error(u->id,
				"More than one OnFailure= dependencies specified for %s but OnFailureJobMode=isolate set. Refusing.",
				u->id);
			r = -EINVAL;
			goto fail;
		}

		unit_update_cgroup_members_masks(u);
	}

	assert((u->load_state != UNIT_MERGED) == !u->merged_into);

	unit_add_to_dbus_queue(unit_follow_merge(u));
	unit_add_to_gc_queue(u);

	return 0;

fail:
	u->load_state =
		u->load_state == UNIT_STUB ? UNIT_NOT_FOUND : UNIT_ERROR;
	u->load_error = r;
	unit_add_to_dbus_queue(u);
	unit_add_to_gc_queue(u);

	log_unit_debug(u->id, "Failed to load configuration for %s: %s", u->id,
		strerror(-r));

	return r;
}

static bool
unit_condition_test_list(Unit *u, Condition *first,
	const char *(*to_string)(ConditionType t))
{
	Condition *c;
	int triggered = -1;

	assert(u);
	assert(to_string);

	/* If the condition list is empty, then it is true */
	if (!first)
		return true;

	/* Otherwise, if all of the non-trigger conditions apply and
         * if any of the trigger conditions apply (unless there are
         * none) we return true */
	IWLIST_FOREACH (conditions, c, first) {
		int r;

		r = condition_test(c);
		if (r < 0)
			log_unit_warning(u->id,
				"Couldn't determine result for %s=%s%s%s for %s, assuming failed: %s",
				to_string(c->type), c->trigger ? "|" : "",
				c->negate ? "!" : "", c->parameter, u->id,
				strerror(-r));
		else
			log_unit_debug(u->id, "%s=%s%s%s %s for %s.",
				to_string(c->type), c->trigger ? "|" : "",
				c->negate ? "!" : "", c->parameter,
				condition_result_to_string(c->result), u->id);

		if (!c->trigger && r <= 0)
			return false;

		if (c->trigger && triggered <= 0)
			triggered = r > 0;
	}

	return triggered != 0;
}

static bool
unit_condition_test(Unit *u)
{
	assert(u);

	dual_timestamp_get(&u->condition_timestamp);
	u->condition_result = unit_condition_test_list(u, u->conditions,
		condition_type_to_string);

	return u->condition_result;
}

static bool
unit_assert_test(Unit *u)
{
	assert(u);

	dual_timestamp_get(&u->assert_timestamp);
	u->assert_result =
		unit_condition_test_list(u, u->asserts, assert_type_to_string);

	return u->assert_result;
}

_pure_ static const char *
unit_get_status_message_format(Unit *u, JobType t)
{
	const char *format;
	const UnitStatusMessageFormats *format_table;

	assert(u);
	assert(t == JOB_START || t == JOB_STOP || t == JOB_RELOAD);

	if (t != JOB_RELOAD) {
		format_table = &UNIT_VTABLE(u)->status_message_formats;
		if (format_table) {
			format = format_table->starting_stopping[t == JOB_STOP];
			if (format)
				return format;
		}
	}

	/* Return generic strings */
	if (t == JOB_START)
		return "Starting %s.";
	else if (t == JOB_STOP)
		return "Stopping %s.";
	else
		return "Reloading %s.";
}

static void
unit_status_print_starting_stopping(Unit *u, JobType t)
{
	const char *format;

	assert(u);

	format = unit_get_status_message_format(u, t);

	DISABLE_WARNING_FORMAT_NONLITERAL;
	unit_status_printf(u, "", format);
	REENABLE_WARNING;
}

static void
unit_status_log_starting_stopping_reloading(Unit *u, JobType t)
{
	const char *format;
	char buf[LINE_MAX];
	sd_id128_t mid;

	assert(u);

	if (t != JOB_START && t != JOB_STOP && t != JOB_RELOAD)
		return;

	if (log_on_console())
		return;

	/* We log status messages for all units and all operations. */

	format = unit_get_status_message_format(u, t);

	DISABLE_WARNING_FORMAT_NONLITERAL;
	snprintf(buf, sizeof(buf), format, unit_description(u));
	REENABLE_WARNING;

	mid = t == JOB_START  ? SD_MESSAGE_UNIT_STARTING :
		t == JOB_STOP ? SD_MESSAGE_UNIT_STOPPING :
				      SD_MESSAGE_UNIT_RELOADING;

	log_unit_struct(u->id, LOG_INFO, LOG_MESSAGE_ID(mid),
		LOG_MESSAGE("%s", buf), NULL);
}

void
unit_status_emit_starting_stopping_reloading(Unit *u, JobType t)
{
	unit_status_log_starting_stopping_reloading(u, t);

	/* Reload status messages have traditionally not been printed to console. */
	if (t != JOB_RELOAD)
		unit_status_print_starting_stopping(u, t);
}

/* Errors:
 *         -EBADR:     This unit type does not support starting.
 *         -EALREADY:  Unit is already started.
 *         -EAGAIN:    An operation is already in progress. Retry later.
 *         -ECANCELED: Too many requests for now.
 *         -EPROTO:    Assert failed
 */
int
unit_start(Unit *u)
{
	UnitActiveState state;
	Unit *following;

	assert(u);

	if (u->load_state != UNIT_LOADED)
		return -EINVAL;

	/* If this is already started, then this will succeed. Note
         * that this will even succeed if this unit is not startable
         * by the user. This is relied on to detect when we need to
         * wait for units and when waiting is finished. */
	state = unit_active_state(u);
	if (UNIT_IS_ACTIVE_OR_RELOADING(state))
		return -EALREADY;

	/* If the conditions failed, don't do anything at all. If we
         * already are activating this call might still be useful to
         * speed up activation in case there is some hold-off time,
         * but we don't want to recheck the condition in that case. */
	if (state != UNIT_ACTIVATING && !unit_condition_test(u)) {
		log_unit_debug(u->id,
			"Starting of %s requested but condition failed. Not starting unit.",
			u->id);
		return -EALREADY;
	}

	/* If the asserts failed, fail the entire job */
	if (state != UNIT_ACTIVATING && !unit_assert_test(u)) {
		log_unit_debug(u->id,
			"Starting of %s requested but asserts failed.", u->id);
		return -EPROTO;
	}

	/* Forward to the main object, if we aren't it. */
	following = unit_following(u);
	if (following) {
		log_unit_debug(u->id,
			"Redirecting start request from %s to %s.", u->id,
			following->id);
		return unit_start(following);
	}

	if (UNIT_VTABLE(u)->supported && !UNIT_VTABLE(u)->supported(u->manager))
		return -ENOTSUP;

	/* If it is stopped, but we cannot start it, then fail */
	if (!UNIT_VTABLE(u)->start)
		return -EBADR;

	/* We don't suppress calls to ->start() here when we are
         * already starting, to allow this request to be used as a
         * "hurry up" call, for example when the unit is in some "auto
         * restart" state where it waits for a holdoff timer to elapse
         * before it will start again. */

	unit_add_to_dbus_queue(u);

	return UNIT_VTABLE(u)->start(u);
}

bool
unit_can_start(Unit *u)
{
	assert(u);

	return !!UNIT_VTABLE(u)->start;
}

bool
unit_can_isolate(Unit *u)
{
	assert(u);

	return unit_can_start(u) && u->allow_isolate;
}

/* Errors:
 *         -EBADR:    This unit type does not support stopping.
 *         -EALREADY: Unit is already stopped.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int
unit_stop(Unit *u)
{
	UnitActiveState state;
	Unit *following;

	assert(u);

	state = unit_active_state(u);
	if (UNIT_IS_INACTIVE_OR_FAILED(state))
		return -EALREADY;

	following = unit_following(u);
	if (following) {
		log_unit_debug(u->id, "Redirecting stop request from %s to %s.",
			u->id, following->id);
		return unit_stop(following);
	}

	if (!UNIT_VTABLE(u)->stop)
		return -EBADR;

	unit_add_to_dbus_queue(u);

	return UNIT_VTABLE(u)->stop(u);
}

/* Errors:
 *         -EBADR:    This unit type does not support reloading.
 *         -ENOEXEC:  Unit is not started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int
unit_reload(Unit *u)
{
	UnitActiveState state;
	Unit *following;

	assert(u);

	if (u->load_state != UNIT_LOADED)
		return -EINVAL;

	if (!unit_can_reload(u))
		return -EBADR;

	state = unit_active_state(u);
	if (state == UNIT_RELOADING)
		return -EALREADY;

	if (state != UNIT_ACTIVE) {
		log_unit_warning(u->id,
			"Unit %s cannot be reloaded because it is inactive.",
			u->id);
		return -ENOEXEC;
	}

	following = unit_following(u);
	if (following) {
		log_unit_debug(u->id,
			"Redirecting reload request from %s to %s.", u->id,
			following->id);
		return unit_reload(following);
	}

	unit_add_to_dbus_queue(u);

	return UNIT_VTABLE(u)->reload(u);
}

bool
unit_can_reload(Unit *u)
{
	assert(u);

	if (!UNIT_VTABLE(u)->reload)
		return false;

	if (!UNIT_VTABLE(u)->can_reload)
		return true;

	return UNIT_VTABLE(u)->can_reload(u);
}

bool
unit_is_unneeded(Unit *u)
{
	static const UnitDependency deps[] = {
		UNIT_REQUIRED_BY,
		UNIT_REQUIRED_BY_OVERRIDABLE,
		UNIT_WANTED_BY,
		UNIT_BOUND_BY,
	};
	size_t j;

	assert(u);

	if (!u->stop_when_unneeded)
		return false;

	/* Don't clean up while the unit is transitioning or is even inactive. */
	if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
		return false;
	if (u->job)
		return false;

	for (j = 0; j < ELEMENTSOF(deps); j++) {
		Unit *other;
		Iterator i;

		/* If a dependending unit has a job queued, or is active (or in transitioning), or is marked for
                 * restart, then don't clean this one up. */

		SET_FOREACH (other, u->dependencies[deps[j]], i) {
			if (u->job)
				return false;

			if (!UNIT_IS_INACTIVE_OR_FAILED(
				    unit_active_state(other)))
				return false;
		}
	}

	return true;
}

static void
check_unneeded_dependencies(Unit *u)
{
	static const UnitDependency deps[] = {
		UNIT_REQUIRES,
		UNIT_REQUIRES_OVERRIDABLE,
		UNIT_REQUISITE,
		UNIT_REQUISITE_OVERRIDABLE,
		UNIT_WANTS,
		UNIT_BINDS_TO,
	};
	size_t j;

	assert(u);

	/* Add all units this unit depends on to the queue that processes StopWhenUnneeded= behaviour. */

	for (j = 0; j < ELEMENTSOF(deps); j++) {
		Unit *other;
		Iterator i;

		SET_FOREACH (other, u->dependencies[deps[j]], i)
			unit_add_to_stop_when_unneeded_queue(other);
	}
}

static void
unit_check_binds_to(Unit *u)
{
	bool stop = false;
	Unit *other;
	Iterator i;

	assert(u);

	if (u->job)
		return;

	if (unit_active_state(u) != UNIT_ACTIVE)
		return;

	SET_FOREACH (other, u->dependencies[UNIT_BINDS_TO], i) {
		if (other->job)
			continue;

		if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other)))
			continue;

		stop = true;
		break;
	}

	if (!stop)
		return;

	assert(other);
	log_unit_info(u->id,
		"Unit %s is bound to inactive unit %s. Stopping, too.", u->id,
		other->id);

	/* A unit we need to run is gone. Sniff. Let's stop this. */
	manager_add_job(u->manager, JOB_STOP, u, JOB_FAIL, true, NULL, NULL);
}

static void
retroactively_start_dependencies(Unit *u)
{
	Iterator i;
	Unit *other;

	assert(u);
	assert(UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)));

	SET_FOREACH (other, u->dependencies[UNIT_REQUIRES], i)
		if (!set_get(u->dependencies[UNIT_AFTER], other) &&
			!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_START, other,
				JOB_REPLACE, true, NULL, NULL);

	SET_FOREACH (other, u->dependencies[UNIT_BINDS_TO], i)
		if (!set_get(u->dependencies[UNIT_AFTER], other) &&
			!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_START, other,
				JOB_REPLACE, true, NULL, NULL);

	SET_FOREACH (other, u->dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
		if (!set_get(u->dependencies[UNIT_AFTER], other) &&
			!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_START, other, JOB_FAIL,
				false, NULL, NULL);

	SET_FOREACH (other, u->dependencies[UNIT_WANTS], i)
		if (!set_get(u->dependencies[UNIT_AFTER], other) &&
			!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_START, other, JOB_FAIL,
				false, NULL, NULL);

	SET_FOREACH (other, u->dependencies[UNIT_CONFLICTS], i)
		if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_STOP, other,
				JOB_REPLACE, true, NULL, NULL);

	SET_FOREACH (other, u->dependencies[UNIT_CONFLICTED_BY], i)
		if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_STOP, other,
				JOB_REPLACE, true, NULL, NULL);
}

static void
retroactively_stop_dependencies(Unit *u)
{
	Iterator i;
	Unit *other;

	assert(u);
	assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

	/* Pull down units which are bound to us recursively if enabled */
	SET_FOREACH (other, u->dependencies[UNIT_BOUND_BY], i)
		if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
			manager_add_job(u->manager, JOB_STOP, other,
				JOB_REPLACE, true, NULL, NULL);
}

void
unit_start_on_failure(Unit *u)
{
	Unit *other;
	Iterator i;

	assert(u);

	if (set_size(u->dependencies[UNIT_ON_FAILURE]) <= 0)
		return;

	log_unit_info(u->id, "Triggering OnFailure= dependencies of %s.",
		u->id);

	SET_FOREACH (other, u->dependencies[UNIT_ON_FAILURE], i) {
		int r;

		r = manager_add_job(u->manager, JOB_START, other,
			u->on_failure_job_mode, true, NULL, NULL);
		if (r < 0)
			log_unit_error_errno(u->id, r,
				"Failed to enqueue OnFailure= job: %m");
	}
}

void
unit_trigger_notify(Unit *u)
{
	Unit *other;
	Iterator i;

	assert(u);

	SET_FOREACH (other, u->dependencies[UNIT_TRIGGERED_BY], i)
		if (UNIT_VTABLE(other)->trigger_notify)
			UNIT_VTABLE(other)->trigger_notify(other, u);
}

static void
unit_update_on_console(Unit *u)
{
	bool b;

	assert(u);

	b = unit_needs_console(u);
	if (u->on_console == b)
		return;

	u->on_console = b;
	if (b)
		manager_ref_console(u->manager);
	else
		manager_unref_console(u->manager);
}

void
unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns,
	bool reload_success)
{
	Manager *m;
	bool unexpected;

	assert(u);
	assert(os < _UNIT_ACTIVE_STATE_MAX);
	assert(ns < _UNIT_ACTIVE_STATE_MAX);

	/* Note that this is called for all low-level state changes,
         * even if they might map to the same high-level
         * UnitActiveState! That means that ns == os is an expected
         * behavior here. For example: if a mount point is remounted
         * this function will be called too! */

	m = u->manager;

	/* Update timestamps for state changes */
	if (m->n_reloading <= 0) {
		dual_timestamp ts;

		dual_timestamp_get(&ts);

		if (UNIT_IS_INACTIVE_OR_FAILED(os) &&
			!UNIT_IS_INACTIVE_OR_FAILED(ns))
			u->inactive_exit_timestamp = ts;
		else if (!UNIT_IS_INACTIVE_OR_FAILED(os) &&
			UNIT_IS_INACTIVE_OR_FAILED(ns))
			u->inactive_enter_timestamp = ts;

		if (!UNIT_IS_ACTIVE_OR_RELOADING(os) &&
			UNIT_IS_ACTIVE_OR_RELOADING(ns))
			u->active_enter_timestamp = ts;
		else if (UNIT_IS_ACTIVE_OR_RELOADING(os) &&
			!UNIT_IS_ACTIVE_OR_RELOADING(ns))
			u->active_exit_timestamp = ts;
	}

	/* Keep track of failed units */
	if (ns == UNIT_FAILED)
		set_put(u->manager->failed_units, u);
	else
		set_remove(u->manager->failed_units, u);

	/* Make sure the cgroup is always removed when we become inactive */
	if (UNIT_IS_INACTIVE_OR_FAILED(ns))
		unit_destroy_cgroup_if_empty(u);

	unit_update_on_console(u);

	if (u->job) {
		unexpected = false;

		if (u->job->state == JOB_WAITING)

			/* So we reached a different state for this
                         * job. Let's see if we can run it now if it
                         * failed previously due to EAGAIN. */
			job_add_to_run_queue(u->job);

		/* Let's check whether this state change constitutes a
                 * finished job, or maybe contradicts a running job and
                 * hence needs to invalidate jobs. */

		switch (u->job->type) {
		case JOB_START:
		case JOB_VERIFY_ACTIVE:

			if (UNIT_IS_ACTIVE_OR_RELOADING(ns))
				job_finish_and_invalidate(u->job, JOB_DONE,
					true, false);
			else if (u->job->state == JOB_RUNNING &&
				ns != UNIT_ACTIVATING) {
				unexpected = true;

				if (UNIT_IS_INACTIVE_OR_FAILED(ns))
					job_finish_and_invalidate(u->job,
						ns == UNIT_FAILED ? JOB_FAILED :
									  JOB_DONE,
						true, false);
			}

			break;

		case JOB_RELOAD:
		case JOB_RELOAD_OR_START:
		case JOB_TRY_RELOAD:

			if (u->job->state == JOB_RUNNING) {
				if (ns == UNIT_ACTIVE)
					job_finish_and_invalidate(u->job,
						reload_success ? JOB_DONE :
								       JOB_FAILED,
						true, false);
				else if (ns != UNIT_ACTIVATING &&
					ns != UNIT_RELOADING) {
					unexpected = true;

					if (UNIT_IS_INACTIVE_OR_FAILED(ns))
						job_finish_and_invalidate(
							u->job,
							ns == UNIT_FAILED ?
								      JOB_FAILED :
								      JOB_DONE,
							true, false);
				}
			}

			break;

		case JOB_STOP:
		case JOB_RESTART:
		case JOB_TRY_RESTART:

			if (UNIT_IS_INACTIVE_OR_FAILED(ns))
				job_finish_and_invalidate(u->job, JOB_DONE,
					true, false);
			else if (u->job->state == JOB_RUNNING &&
				ns != UNIT_DEACTIVATING) {
				unexpected = true;
				job_finish_and_invalidate(u->job, JOB_FAILED,
					true, false);
			}

			break;

		default:
			assert_not_reached();
		}

	} else
		unexpected = true;

	if (m->n_reloading <= 0) {
		/* If this state change happened without being
                 * requested by a job, then let's retroactively start
                 * or stop dependencies. We skip that step when
                 * deserializing, since we don't want to create any
                 * additional jobs just because something is already
                 * activated. */

		if (unexpected) {
			if (UNIT_IS_INACTIVE_OR_FAILED(os) &&
				UNIT_IS_ACTIVE_OR_ACTIVATING(ns))
				retroactively_start_dependencies(u);
			else if (UNIT_IS_ACTIVE_OR_ACTIVATING(os) &&
				UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
				retroactively_stop_dependencies(u);
		}

		/* stop unneeded units regardless if going down was expected or not */
		if (UNIT_IS_INACTIVE_OR_FAILED(ns))
			check_unneeded_dependencies(u);

		if (ns != os && ns == UNIT_FAILED) {
			log_unit_notice(u->id, "Unit %s entered failed state.",
				u->id);
			unit_start_on_failure(u);
		}
	}

	/* Some names are special */
	if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {
		if (unit_has_name(u, SPECIAL_DBUS_SERVICE))
			/* The bus might have just become available,
                         * hence try to connect to it, if we aren't
                         * yet connected. */
			bus_init(m, true);

#ifdef SVC_USE_Audit
		if (u->type == UNIT_SERVICE &&
			!UNIT_IS_ACTIVE_OR_RELOADING(os) &&
			m->n_reloading <= 0) {
			/* Write audit record if we have just finished starting up */
			manager_send_unit_audit(m, u, AUDIT_SERVICE_START,
				true);
			u->in_audit = true;
		}
#endif

		if (!UNIT_IS_ACTIVE_OR_RELOADING(os))
			manager_send_unit_plymouth(m, u);

	} else {
		/* We don't care about D-Bus here, since we'll get an
                 * asynchronous notification for it anyway. */

		if (u->type == UNIT_SERVICE && UNIT_IS_INACTIVE_OR_FAILED(ns) &&
			!UNIT_IS_INACTIVE_OR_FAILED(os) &&
			m->n_reloading <= 0) {
			/* Hmm, if there was no start record written
                         * write it now, so that we always have a nice
                         * pair */
#ifdef SVC_USE_Audit
			if (!u->in_audit) {
				manager_send_unit_audit(m, u,
					AUDIT_SERVICE_START,
					ns == UNIT_INACTIVE);

				if (ns == UNIT_INACTIVE)
					manager_send_unit_audit(m, u,
						AUDIT_SERVICE_STOP, true);
			} else
				/* Write audit record if we have just finished shutting down */
				manager_send_unit_audit(m, u,
					AUDIT_SERVICE_STOP,
					ns == UNIT_INACTIVE);
#endif

			u->in_audit = false;
		}
	}

	manager_recheck_journal(m);
	unit_trigger_notify(u);

	if (u->manager->n_reloading <= 0) {
		/* Maybe we finished startup and are now ready for
                 * being stopped because unneeded? */
		unit_add_to_stop_when_unneeded_queue(u);

		/* Maybe we finished startup, but something we needed
                 * has vanished? Let's die then. (This happens when
                 * something BindsTo= to a Type=oneshot unit, as these
                 * units go directly from starting to inactive,
                 * without ever entering started.) */
		unit_check_binds_to(u);
	}

	unit_add_to_dbus_queue(u);
	unit_add_to_gc_queue(u);
}

int
unit_watch_pid(Unit *u, pid_t pid, bool exclusive)
{
	int q, r;

	assert(u);
	assert(pid >= 1);

	/* Watch a specific PID. We only support one or two units
         * watching each PID for now, not more. */

	/* Caller might be sure that this PID belongs to this unit only. Let's take this
         * opportunity to remove any stalled references to this PID as they can be created
         * easily (when watching a process which is not our direct child). */
	if (exclusive) {
		log_unit_debug(u->id, "Cleaning " PID_FMT " from watches.",
			pid);
		hashmap_remove2(u->manager->watch_pids1, LONG_TO_PTR(pid),
			NULL);
		hashmap_remove2(u->manager->watch_pids2, LONG_TO_PTR(pid),
			NULL);
	}

	r = set_ensure_allocated(&u->pids, NULL);
	if (r < 0)
		return r;

	r = hashmap_ensure_allocated(&u->manager->watch_pids1, NULL);
	if (r < 0)
		return r;

	r = hashmap_put(u->manager->watch_pids1, LONG_TO_PTR(pid), u);
	if (r == -EEXIST) {
		r = hashmap_ensure_allocated(&u->manager->watch_pids2, NULL);
		if (r < 0)
			return r;

		r = hashmap_put(u->manager->watch_pids2, LONG_TO_PTR(pid), u);
		if (r >= 0)
			log_unit_debug(u->id,
				"Watching " PID_FMT " through watch_pids2.",
				pid);
		else if (r == -EEXIST)
			log_unit_warning(u->id,
				"Cannot watch " PID_FMT
				", PID is already watched twice.",
				pid);
	} else if (r >= 0)
		log_unit_debug(u->id,
			"Watching " PID_FMT " through watch_pids1.", pid);

	q = set_put(u->pids, LONG_TO_PTR(pid));
	if (q < 0)
		return q;

	return r;
}

void
unit_unwatch_pid(Unit *u, pid_t pid)
{
	assert(u);
	assert(pid >= 1);

	log_unit_debug(u->id, "Unwatching " PID_FMT ".", pid);

	hashmap_remove_value(u->manager->watch_pids1, LONG_TO_PTR(pid), u);
	hashmap_remove_value(u->manager->watch_pids2, LONG_TO_PTR(pid), u);
	set_remove(u->pids, LONG_TO_PTR(pid));
}

void
unit_unwatch_all_pids(Unit *u)
{
	assert(u);

	while (!set_isempty(u->pids))
		unit_unwatch_pid(u, PTR_TO_LONG(set_first(u->pids)));

	set_free(u->pids);
	u->pids = NULL;
}

static int
unit_watch_pids_in_path(Unit *u, const char *path)
{
	_cleanup_closedir_ DIR *d = NULL;
	_cleanup_fclose_ FILE *f = NULL;
	int ret = 0, r;

	assert(u);
	assert(path);

	/* Adds all PIDs from a specific cgroup path to the set of PIDs we watch. */

	r = cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, path, &f);
	if (r >= 0) {
		pid_t pid;

		while ((r = cg_read_pid(f, &pid)) > 0) {
			if (pid_is_my_child(pid) == 0)
				log_unit_debug(u->id,
					"Watching non detached " PID_FMT ".",
					pid);
			r = unit_watch_pid(u, pid, false);
			if (r < 0 && ret >= 0)
				ret = r;
		}
		if (r < 0 && ret >= 0)
			ret = r;

	} else
		ret = r;

	r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
	if (r >= 0) {
		char *fn;

		while ((r = cg_read_subgroup(d, &fn)) > 0) {
			_cleanup_free_ char *p = NULL;

			p = strjoin(path, "/", fn, NULL);
			free(fn);

			if (!p)
				return -ENOMEM;

			r = unit_watch_pids_in_path(u, p);
			if (r < 0 && ret >= 0)
				ret = r;
		}
		if (r < 0 && ret >= 0)
			ret = r;

	} else if (ret >= 0)
		ret = r;

	return ret;
}

int
unit_watch_all_pids(Unit *u)
{
	assert(u);

	/* Adds all PIDs from our cgroup to the set of PIDs we watch */

	if (!u->cgroup_path)
		return -ENOENT;

	return unit_watch_pids_in_path(u, u->cgroup_path);
}

void
unit_tidy_watch_pids(Unit *u, pid_t except1, pid_t except2)
{
	Iterator i;
	void *e;

	assert(u);

	/* Cleans dead PIDs from our list */

	SET_FOREACH (e, u->pids, i) {
		pid_t pid = PTR_TO_LONG(e);

		if (pid == except1 || pid == except2)
			continue;

		if (!pid_is_unwaited(pid))
			unit_unwatch_pid(u, pid);
	}
}

bool
unit_job_is_applicable(Unit *u, JobType j)
{
	assert(u);
	assert(j >= 0 && j < _JOB_TYPE_MAX);

	switch (j) {
	case JOB_VERIFY_ACTIVE:
	case JOB_START:
	case JOB_STOP:
	case JOB_NOP:
		return true;

	case JOB_RESTART:
	case JOB_TRY_RESTART:
		return unit_can_start(u);

	case JOB_RELOAD:
	case JOB_TRY_RELOAD:
		return unit_can_reload(u);

	case JOB_RELOAD_OR_START:
		return unit_can_reload(u) && unit_can_start(u);

	default:
		assert_not_reached();
	}
}

static int
maybe_warn_about_dependency(const char *id, const char *other,
	UnitDependency dependency)
{
	assert(id);

	switch (dependency) {
	case UNIT_REQUIRES:
	case UNIT_REQUIRES_OVERRIDABLE:
	case UNIT_WANTS:
	case UNIT_REQUISITE:
	case UNIT_REQUISITE_OVERRIDABLE:
	case UNIT_BINDS_TO:
	case UNIT_PART_OF:
	case UNIT_REQUIRED_BY:
	case UNIT_REQUIRED_BY_OVERRIDABLE:
	case UNIT_WANTED_BY:
	case UNIT_BOUND_BY:
	case UNIT_CONSISTS_OF:
	case UNIT_REFERENCES:
	case UNIT_REFERENCED_BY:
	case UNIT_PROPAGATES_RELOAD_TO:
	case UNIT_RELOAD_PROPAGATED_FROM:
	case UNIT_JOINS_NAMESPACE_OF:
		return 0;

	case UNIT_CONFLICTS:
	case UNIT_CONFLICTED_BY:
	case UNIT_BEFORE:
	case UNIT_AFTER:
	case UNIT_ON_FAILURE:
	case UNIT_TRIGGERS:
	case UNIT_TRIGGERED_BY:
		if (streq_ptr(id, other))
			log_unit_warning(id,
				"Dependency %s=%s dropped from unit %s",
				unit_dependency_to_string(dependency), id,
				other);
		else
			log_unit_warning(id,
				"Dependency %s=%s dropped from unit %s merged into %s",
				unit_dependency_to_string(dependency), id,
				strna(other), id);
		return -EINVAL;

	case _UNIT_DEPENDENCY_MAX:
	case _UNIT_DEPENDENCY_INVALID:
		break;
	}

	assert_not_reached();
}

int
unit_add_dependency(Unit *u, UnitDependency d, Unit *other, bool add_reference)
{
	static const UnitDependency inverse_table[_UNIT_DEPENDENCY_MAX] = {
		[UNIT_REQUIRES] = UNIT_REQUIRED_BY,
		[UNIT_REQUIRES_OVERRIDABLE] = UNIT_REQUIRED_BY_OVERRIDABLE,
		[UNIT_WANTS] = UNIT_WANTED_BY,
		[UNIT_REQUISITE] = UNIT_REQUIRED_BY,
		[UNIT_REQUISITE_OVERRIDABLE] = UNIT_REQUIRED_BY_OVERRIDABLE,
		[UNIT_BINDS_TO] = UNIT_BOUND_BY,
		[UNIT_PART_OF] = UNIT_CONSISTS_OF,
		[UNIT_REQUIRED_BY] = _UNIT_DEPENDENCY_INVALID,
		[UNIT_REQUIRED_BY_OVERRIDABLE] = _UNIT_DEPENDENCY_INVALID,
		[UNIT_WANTED_BY] = _UNIT_DEPENDENCY_INVALID,
		[UNIT_BOUND_BY] = UNIT_BINDS_TO,
		[UNIT_CONSISTS_OF] = UNIT_PART_OF,
		[UNIT_CONFLICTS] = UNIT_CONFLICTED_BY,
		[UNIT_CONFLICTED_BY] = UNIT_CONFLICTS,
		[UNIT_BEFORE] = UNIT_AFTER,
		[UNIT_AFTER] = UNIT_BEFORE,
		[UNIT_ON_FAILURE] = _UNIT_DEPENDENCY_INVALID,
		[UNIT_REFERENCES] = UNIT_REFERENCED_BY,
		[UNIT_REFERENCED_BY] = UNIT_REFERENCES,
		[UNIT_TRIGGERS] = UNIT_TRIGGERED_BY,
		[UNIT_TRIGGERED_BY] = UNIT_TRIGGERS,
		[UNIT_PROPAGATES_RELOAD_TO] = UNIT_RELOAD_PROPAGATED_FROM,
		[UNIT_RELOAD_PROPAGATED_FROM] = UNIT_PROPAGATES_RELOAD_TO,
		[UNIT_JOINS_NAMESPACE_OF] = UNIT_JOINS_NAMESPACE_OF,
	};
	int r, q = 0, v = 0, w = 0;
	Unit *orig_u = u, *orig_other = other;
	/* Helper to know whether sending a notification is necessary or not:
         * if the dependency is already there, no need to notify! */
	bool noop = true;

	assert(u);
	assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
	assert(other);

	u = unit_follow_merge(u);
	other = unit_follow_merge(other);

	/* We won't allow dependencies on ourselves. We will not
         * consider them an error however. */
	if (u == other) {
		maybe_warn_about_dependency(orig_u->id, orig_other->id, d);
		return 0;
	}

	r = set_ensure_allocated(&u->dependencies[d], NULL);
	if (r < 0)
		return r;

	if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID) {
		r = set_ensure_allocated(&other->dependencies[inverse_table[d]],
			NULL);
		if (r < 0)
			return r;
	}

	if (add_reference) {
		r = set_ensure_allocated(&u->dependencies[UNIT_REFERENCES],
			NULL);
		if (r < 0)
			return r;

		r = set_ensure_allocated(
			&other->dependencies[UNIT_REFERENCED_BY], NULL);
		if (r < 0)
			return r;
	}

	q = set_put(u->dependencies[d], other);
	if (q < 0)
		return q;
	else if (q > 0)
		noop = false;

	if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID &&
		inverse_table[d] != d) {
		v = set_put(other->dependencies[inverse_table[d]], u);
		if (v < 0) {
			r = v;
			goto fail;
		} else if (v > 0)
			noop = false;
	}

	if (add_reference) {
		w = set_put(u->dependencies[UNIT_REFERENCES], other);
		if (w < 0) {
			r = w;
			goto fail;
		} else if (w > 0)
			noop = false;

		r = set_put(other->dependencies[UNIT_REFERENCED_BY], u);
		if (r < 0)
			goto fail;
		else if (r > 0)
			noop = false;
	}

	if (!noop)
		unit_add_to_dbus_queue(u);
	return 0;

fail:
	if (q > 0)
		set_remove(u->dependencies[d], other);

	if (v > 0)
		set_remove(other->dependencies[inverse_table[d]], u);

	if (w > 0)
		set_remove(u->dependencies[UNIT_REFERENCES], other);

	return r;
}

int
unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e,
	Unit *other, bool add_reference)
{
	int r;

	assert(u);

	r = unit_add_dependency(u, d, other, add_reference);
	if (r < 0)
		return r;

	r = unit_add_dependency(u, e, other, add_reference);
	if (r < 0)
		return r;

	return 0;
}

static const char *
resolve_template(Unit *u, const char *name, const char *path, char **p)
{
	char *s;

	assert(u);
	assert(name || path);
	assert(p);

	if (!name)
		name = lsb_basename(path);

	if (!unit_name_is_template(name)) {
		*p = NULL;
		return name;
	}

	if (u->instance)
		s = unit_name_replace_instance(name, u->instance);
	else {
		_cleanup_free_ char *i = NULL;

		i = unit_name_to_prefix(u->id);
		if (!i)
			return NULL;

		s = unit_name_replace_instance(name, i);
	}

	if (!s)
		return NULL;

	*p = s;
	return s;
}

int
unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name,
	const char *path, bool add_reference)
{
	Unit *other;
	int r;
	_cleanup_free_ char *s = NULL;

	assert(u);
	assert(name || path);

	name = resolve_template(u, name, path, &s);
	if (!name)
		return -ENOMEM;

	r = manager_load_unit(u->manager, name, path, NULL, &other);
	if (r < 0)
		return r;

	return unit_add_dependency(u, d, other, add_reference);
}

int
unit_add_two_dependencies_by_name(Unit *u, UnitDependency d, UnitDependency e,
	const char *name, const char *path, bool add_reference)
{
	_cleanup_free_ char *s = NULL;
	Unit *other;
	int r;

	assert(u);
	assert(name || path);

	name = resolve_template(u, name, path, &s);
	if (!name)
		return -ENOMEM;

	r = manager_load_unit(u->manager, name, path, NULL, &other);
	if (r < 0)
		return r;

	return unit_add_two_dependencies(u, d, e, other, add_reference);
}

int
unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d, const char *name,
	const char *path, bool add_reference)
{
	Unit *other;
	int r;
	_cleanup_free_ char *s = NULL;

	assert(u);
	assert(name || path);

	name = resolve_template(u, name, path, &s);
	if (!name)
		return -ENOMEM;

	r = manager_load_unit(u->manager, name, path, NULL, &other);
	if (r < 0)
		return r;

	return unit_add_dependency(other, d, u, add_reference);
}

int
unit_add_two_dependencies_by_name_inverse(Unit *u, UnitDependency d,
	UnitDependency e, const char *name, const char *path,
	bool add_reference)
{
	Unit *other;
	int r;
	_cleanup_free_ char *s = NULL;

	assert(u);
	assert(name || path);

	name = resolve_template(u, name, path, &s);
	if (!name)
		return -ENOMEM;

	r = manager_load_unit(u->manager, name, path, NULL, &other);
	if (r < 0)
		return r;

	r = unit_add_two_dependencies(other, d, e, u, add_reference);
	if (r < 0)
		return r;

	return r;
}

int
set_unit_path(const char *p)
{
	/* This is mostly for debug purposes */
	if (setenv("SYSTEMD_UNIT_PATH", p, 0) < 0)
		return -errno;

	return 0;
}

char *
unit_dbus_path(Unit *u)
{
	assert(u);

	if (!u->id)
		return NULL;

	return unit_dbus_path_from_name(u->id);
}

char *
unit_default_cgroup_path(Unit *u)
{
	_cleanup_free_ char *escaped = NULL, *slice = NULL;
	int r;

	assert(u);

	if (unit_has_name(u, SPECIAL_ROOT_SLICE))
		return strdup(u->manager->cgroup_root);

	if (UNIT_ISSET(u->slice) &&
		!unit_has_name(UNIT_DEREF(u->slice), SPECIAL_ROOT_SLICE)) {
		r = cg_slice_to_path(UNIT_DEREF(u->slice)->id, &slice);
		if (r < 0)
			return NULL;
	}

	escaped = cg_escape(u->id);
	if (!escaped)
		return NULL;

	if (slice)
		return strjoin(u->manager->cgroup_root, "/", slice, "/",
			escaped, NULL);
	else
		return strjoin(u->manager->cgroup_root, "/", escaped, NULL);
}

int
unit_add_default_slice(Unit *u, CGroupContext *c)
{
	_cleanup_free_ char *b = NULL;
	const char *slice_name;
	Unit *slice;
	int r;

	assert(u);
	assert(c);

	if (UNIT_ISSET(u->slice))
		return 0;

	if (u->instance) {
		_cleanup_free_ char *prefix = NULL, *escaped = NULL;

		/* Implicitly place all instantiated units in their
                 * own per-template slice */

		prefix = unit_name_to_prefix(u->id);
		if (!prefix)
			return -ENOMEM;

		/* The prefix is already escaped, but it might include
                 * "-" which has a special meaning for slice units,
                 * hence escape it here extra. */
		escaped = strreplace(prefix, "-", "\\x2d");
		if (!escaped)
			return -ENOMEM;

		if (u->manager->running_as == SYSTEMD_SYSTEM)
			b = strjoin("system-", escaped, ".slice", NULL);
		else
			b = strappend(escaped, ".slice");
		if (!b)
			return -ENOMEM;

		slice_name = b;
	} else
		slice_name = u->manager->running_as == SYSTEMD_SYSTEM ?
			      SPECIAL_SYSTEM_SLICE :
			      SPECIAL_ROOT_SLICE;

	r = manager_load_unit(u->manager, slice_name, NULL, NULL, &slice);
	if (r < 0)
		return r;

	unit_ref_set(&u->slice, u, slice);
	return 0;
}

const char *
unit_slice_name(Unit *u)
{
	assert(u);

	if (!UNIT_ISSET(u->slice))
		return NULL;

	return UNIT_DEREF(u->slice)->id;
}

int
unit_load_related_unit(Unit *u, const char *type, Unit **_found)
{
	_cleanup_free_ char *t = NULL;
	int r;

	assert(u);
	assert(type);
	assert(_found);

	t = unit_name_change_suffix(u->id, type);
	if (!t)
		return -ENOMEM;

	assert(!unit_has_name(u, t));

	r = manager_load_unit(u->manager, t, NULL, NULL, _found);
	assert(r < 0 || *_found != u);
	return r;
}

int
unit_watch_bus_name(Unit *u, const char *name)
{
	assert(u);
	assert(name);

	/* Watch a specific name on the bus. We only support one unit
         * watching each name for now. */

	return hashmap_put(u->manager->watch_bus, name, u);
}

void
unit_unwatch_bus_name(Unit *u, const char *name)
{
	assert(u);
	assert(name);

	hashmap_remove_value(u->manager->watch_bus, name, u);
}

bool
unit_can_serialize(Unit *u)
{
	assert(u);

	return UNIT_VTABLE(u)->serialize && UNIT_VTABLE(u)->deserialize_item;
}

int
unit_serialize(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs)
{
	int r;

	assert(u);
	assert(f);
	assert(fds);

	if (unit_can_serialize(u)) {
		ExecRuntime *rt;

		r = UNIT_VTABLE(u)->serialize(u, f, fds);
		if (r < 0)
			return r;

		rt = unit_get_exec_runtime(u);
		if (rt) {
			r = exec_runtime_serialize(rt, u, f, fds);
			if (r < 0)
				return r;
		}
	}

	dual_timestamp_serialize(f, "inactive-exit-timestamp",
		&u->inactive_exit_timestamp);
	dual_timestamp_serialize(f, "active-enter-timestamp",
		&u->active_enter_timestamp);
	dual_timestamp_serialize(f, "active-exit-timestamp",
		&u->active_exit_timestamp);
	dual_timestamp_serialize(f, "inactive-enter-timestamp",
		&u->inactive_enter_timestamp);
	dual_timestamp_serialize(f, "condition-timestamp",
		&u->condition_timestamp);
	dual_timestamp_serialize(f, "assert-timestamp", &u->assert_timestamp);

	if (dual_timestamp_is_set(&u->condition_timestamp))
		unit_serialize_item(u, f, "condition-result",
			yes_no(u->condition_result));

	if (dual_timestamp_is_set(&u->assert_timestamp))
		unit_serialize_item(u, f, "assert-result",
			yes_no(u->assert_result));

	unit_serialize_item(u, f, "transient", yes_no(u->transient));

	if (u->cgroup_path)
		unit_serialize_item(u, f, "cgroup", u->cgroup_path);
	unit_serialize_item(u, f, "cgroup-realized",
		yes_no(u->cgroup_realized));

	if (serialize_jobs) {
		if (u->job) {
			fprintf(f, "job\n");
			job_serialize(u->job, f, fds);
		}

		if (u->nop_job) {
			fprintf(f, "job\n");
			job_serialize(u->nop_job, f, fds);
		}
	}

	/* End marker */
	fputc('\n', f);
	return 0;
}

void
unit_serialize_item_format(Unit *u, FILE *f, const char *key,
	const char *format, ...)
{
	va_list ap;

	assert(u);
	assert(f);
	assert(key);
	assert(format);

	fputs(key, f);
	fputc('=', f);

	va_start(ap, format);
	vfprintf(f, format, ap);
	va_end(ap);

	fputc('\n', f);
}

void
unit_serialize_item(Unit *u, FILE *f, const char *key, const char *value)
{
	assert(u);
	assert(f);
	assert(key);
	assert(value);

	fprintf(f, "%s=%s\n", key, value);
}

int
unit_deserialize(Unit *u, FILE *f, FDSet *fds)
{
	ExecRuntime **rt = NULL;
	size_t offset;
	int r;

	assert(u);
	assert(f);
	assert(fds);

	offset = UNIT_VTABLE(u)->exec_runtime_offset;
	if (offset > 0)
		rt = (ExecRuntime **)((uint8_t *)u + offset);

	for (;;) {
		_cleanup_free_ char *line = NULL;
		char *l, *v;
		size_t k;

		r = read_line(f, LONG_LINE_MAX, &line);
		if (r < 0)
			return log_error_errno(r,
				"Failed to read serialization line: %m");
		if (r == 0) /* eof */
			return 0;

		l = strstrip(line);
		/* End marker */
		if (isempty(l))
			return 0;

		k = strcspn(l, "=");

		if (l[k] == '=') {
			l[k] = 0;
			v = l + k + 1;
		} else
			v = l + k;

		if (streq(l, "job")) {
			if (v[0] == '\0') {
				/* new-style serialized job */
				Job *j;

				j = job_new_raw(u);
				if (!j)
					return -ENOMEM;

				r = job_deserialize(j, f, fds);
				if (r < 0) {
					job_free(j);
					return r;
				}

				r = hashmap_put(u->manager->jobs,
					UINT32_TO_PTR(j->id), j);
				if (r < 0) {
					job_free(j);
					return r;
				}

				r = job_install_deserialized(j);
				if (r < 0) {
					hashmap_remove(u->manager->jobs,
						UINT32_TO_PTR(j->id));
					job_free(j);
					return r;
				}
			} else {
				/* legacy */
				JobType type;

				type = job_type_from_string(v);
				if (type < 0)
					log_debug(
						"Failed to parse job type value %s",
						v);
				else
					u->deserialized_job = type;
			}
			continue;
		} else if (streq(l, "inactive-exit-timestamp")) {
			dual_timestamp_deserialize(v,
				&u->inactive_exit_timestamp);
			continue;
		} else if (streq(l, "active-enter-timestamp")) {
			dual_timestamp_deserialize(v,
				&u->active_enter_timestamp);
			continue;
		} else if (streq(l, "active-exit-timestamp")) {
			dual_timestamp_deserialize(v,
				&u->active_exit_timestamp);
			continue;
		} else if (streq(l, "inactive-enter-timestamp")) {
			dual_timestamp_deserialize(v,
				&u->inactive_enter_timestamp);
			continue;
		} else if (streq(l, "condition-timestamp")) {
			dual_timestamp_deserialize(v, &u->condition_timestamp);
			continue;
		} else if (streq(l, "assert-timestamp")) {
			dual_timestamp_deserialize(v, &u->assert_timestamp);
			continue;
		} else if (streq(l, "condition-result")) {
			int b;

			b = parse_boolean(v);
			if (b < 0)
				log_debug(
					"Failed to parse condition result value %s",
					v);
			else
				u->condition_result = b;

			continue;

		} else if (streq(l, "assert-result")) {
			int b;

			b = parse_boolean(v);
			if (b < 0)
				log_debug(
					"Failed to parse assert result value %s",
					v);
			else
				u->assert_result = b;

			continue;

		} else if (streq(l, "transient")) {
			int b;

			b = parse_boolean(v);
			if (b < 0)
				log_debug("Failed to parse transient bool %s",
					v);
			else
				u->transient = b;

			continue;
		} else if (streq(l, "cgroup")) {
			char *s;

			s = strdup(v);
			if (!s)
				return -ENOMEM;

			if (u->cgroup_path) {
				void *p;

				p = hashmap_remove(u->manager->cgroup_unit,
					u->cgroup_path);
				log_info(
					"Removing cgroup_path %s from hashmap (%p)",
					u->cgroup_path, p);
				free(u->cgroup_path);
			}

			u->cgroup_path = s;
			assert(hashmap_put(u->manager->cgroup_unit, s, u) == 1);

			continue;
		} else if (streq(l, "cgroup-realized")) {
			int b;

			b = parse_boolean(v);
			if (b < 0)
				log_unit_debug(u->id,
					"Failed to parse cgroup-realized bool %s, ignoring.",
					v);
			else
				u->cgroup_realized = b;

			continue;
		}

		if (unit_can_serialize(u)) {
			if (rt) {
				r = exec_runtime_deserialize_item(rt, u, l, v,
					fds);
				if (r < 0)
					return r;
				if (r > 0)
					continue;
			}

			r = UNIT_VTABLE(u)->deserialize_item(u, l, v, fds);
			if (r < 0)
				return r;
		}
	}
}

int
unit_add_node_link(Unit *u, const char *what, bool wants, UnitDependency dep)
{
	Unit *device;
	_cleanup_free_ char *e = NULL;
	int r;

	assert(u);

	/* Adds in links to the device node that this unit is based on */
	if (isempty(what))
		return 0;

	if (!is_device_path(what))
		return 0;

#ifdef SVC_USE_Device
	/* When device units aren't supported (such as in a
         * container), don't create dependencies on them. */
	if (unit_vtable[UNIT_DEVICE]->supported &&
		!unit_vtable[UNIT_DEVICE]->supported(u->manager))
#endif
		return 0;

	e = unit_name_from_path(what, ".device");
	if (!e)
		return -ENOMEM;

	r = manager_load_unit(u->manager, e, NULL, NULL, &device);
	if (r < 0)
		return r;

	r = unit_add_two_dependencies(u, UNIT_AFTER,
		u->manager->running_as == SYSTEMD_SYSTEM ? dep : UNIT_WANTS,
		device, true);
	if (r < 0)
		return r;

	if (wants) {
		r = unit_add_dependency(device, UNIT_WANTS, u, false);
		if (r < 0)
			return r;
	}

	return 0;
}

static int
unit_add_deserialized_job_coldplug(Unit *u)
{
	int r;

	r = manager_add_job(u->manager, u->deserialized_job, u,
		JOB_IGNORE_REQUIREMENTS, false, NULL, NULL);
	if (r < 0)
		return r;

	u->deserialized_job = _JOB_TYPE_INVALID;

	return 0;
}

int
unit_coldplug(Unit *u, Hashmap *deferred_work)
{
	int r;
	Job *uj;

	assert(u);

	if (UNIT_VTABLE(u)->coldplug)
		if ((r = UNIT_VTABLE(u)->coldplug(u, deferred_work)) < 0)
			return r;

	uj = u->job ?: u->nop_job;
	if (uj) {
		r = job_coldplug(uj);
		if (r < 0)
			return r;
	} else if (u->deserialized_job >= 0)
		/* legacy */
		hashmap_put(deferred_work, u,
			&unit_add_deserialized_job_coldplug);

	return 0;
}

void
unit_status_printf(Unit *u, const char *status,
	const char *unit_status_msg_format)
{
	DISABLE_WARNING_FORMAT_NONLITERAL;
	manager_status_printf(u->manager, STATUS_TYPE_NORMAL, status,
		unit_status_msg_format, unit_description(u));
	REENABLE_WARNING;
}

bool
unit_need_daemon_reload(Unit *u)
{
	_cleanup_strv_free_ char **t = NULL;
	char **path;
	struct stat st;
	unsigned loaded_cnt, current_cnt;

	assert(u);

	if (u->fragment_path) {
		zero(st);
		if (stat(u->fragment_path, &st) < 0)
			/* What, cannot access this anymore? */
			return true;

		if (u->fragment_mtime > 0 &&
			timespec_load(&st.st_mtim) != u->fragment_mtime)
			return true;
	}

	if (u->source_path) {
		zero(st);
		if (stat(u->source_path, &st) < 0)
			return true;

		if (u->source_mtime > 0 &&
			timespec_load(&st.st_mtim) != u->source_mtime)
			return true;
	}

	(void)unit_find_dropin_paths(u, &t);
	loaded_cnt = strv_length(t);
	current_cnt = strv_length(u->dropin_paths);

	if (loaded_cnt == current_cnt) {
		if (loaded_cnt == 0)
			return false;

		if (strv_overlap(u->dropin_paths, t)) {
			STRV_FOREACH (path, u->dropin_paths) {
				zero(st);
				if (stat(*path, &st) < 0)
					return true;

				if (u->dropin_mtime > 0 &&
					timespec_load(&st.st_mtim) >
						u->dropin_mtime)
					return true;
			}

			return false;
		} else
			return true;
	} else
		return true;
}

void
unit_reset_failed(Unit *u)
{
	assert(u);

	if (UNIT_VTABLE(u)->reset_failed)
		UNIT_VTABLE(u)->reset_failed(u);
}

Unit *
unit_following(Unit *u)
{
	assert(u);

	if (UNIT_VTABLE(u)->following)
		return UNIT_VTABLE(u)->following(u);

	return NULL;
}

bool
unit_stop_pending(Unit *u)
{
	assert(u);

	/* This call does check the current state of the unit. It's
         * hence useful to be called from state change calls of the
         * unit itself, where the state isn't updated yet. This is
         * different from unit_inactive_or_pending() which checks both
         * the current state and for a queued job. */

	return u->job && u->job->type == JOB_STOP;
}

bool
unit_inactive_or_pending(Unit *u)
{
	assert(u);

	/* Returns true if the unit is inactive or going down */

	if (UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)))
		return true;

	if (unit_stop_pending(u))
		return true;

	return false;
}

bool
unit_active_or_pending(Unit *u)
{
	assert(u);

	/* Returns true if the unit is active or going up */

	if (UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)))
		return true;

	if (u->job &&
		(u->job->type == JOB_START ||
			u->job->type == JOB_RELOAD_OR_START ||
			u->job->type == JOB_RESTART))
		return true;

	return false;
}

int
unit_kill(Unit *u, KillWho w, int signo, sd_bus_error *error)
{
	assert(u);
	assert(w >= 0 && w < _KILL_WHO_MAX);
	assert(signo > 0);
	assert(signo < _NSIG);

	if (!UNIT_VTABLE(u)->kill)
		return -ENOTSUP;

	return UNIT_VTABLE(u)->kill(u, w, signo, error);
}

static Set *
unit_pid_set(pid_t main_pid, pid_t control_pid)
{
	Set *pid_set;
	int r;

	pid_set = set_new(NULL);
	if (!pid_set)
		return NULL;

	/* Exclude the main/control pids from being killed via the cgroup */
	if (main_pid > 0) {
		r = set_put(pid_set, LONG_TO_PTR(main_pid));
		if (r < 0)
			goto fail;
	}

	if (control_pid > 0) {
		r = set_put(pid_set, LONG_TO_PTR(control_pid));
		if (r < 0)
			goto fail;
	}

	return pid_set;

fail:
	set_free(pid_set);
	return NULL;
}

int
unit_kill_common(Unit *u, KillWho who, int signo, pid_t main_pid,
	pid_t control_pid, sd_bus_error *error)
{
	int r = 0;

	if (who == KILL_MAIN && main_pid <= 0) {
		if (main_pid < 0)
			return sd_bus_error_setf(error,
				BUS_ERROR_NO_SUCH_PROCESS,
				"%s units have no main processes",
				unit_type_to_string(u->type));
		else
			return sd_bus_error_set_const(error,
				BUS_ERROR_NO_SUCH_PROCESS,
				"No main process to kill");
	}

	if (who == KILL_CONTROL && control_pid <= 0) {
		if (control_pid < 0)
			return sd_bus_error_setf(error,
				BUS_ERROR_NO_SUCH_PROCESS,
				"%s units have no control processes",
				unit_type_to_string(u->type));
		else
			return sd_bus_error_set_const(error,
				BUS_ERROR_NO_SUCH_PROCESS,
				"No control process to kill");
	}

	if (who == KILL_CONTROL || who == KILL_ALL)
		if (control_pid > 0)
			if (kill(control_pid, signo) < 0)
				r = -errno;

	if (who == KILL_MAIN || who == KILL_ALL)
		if (main_pid > 0)
			if (kill(main_pid, signo) < 0)
				r = -errno;

	if (who == KILL_ALL && u->cgroup_path) {
		_cleanup_set_free_ Set *pid_set = NULL;
		int q;

		/* Exclude the main/control pids from being killed via the cgroup */
		pid_set = unit_pid_set(main_pid, control_pid);
		if (!pid_set)
			return -ENOMEM;

		q = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path,
			signo, false, true, false, pid_set);
		if (q < 0 && q != -EAGAIN && q != -ESRCH && q != -ENOENT)
			r = q;
	}

	return r;
}

int
unit_following_set(Unit *u, Set **s)
{
	assert(u);
	assert(s);

	if (UNIT_VTABLE(u)->following_set)
		return UNIT_VTABLE(u)->following_set(u, s);

	*s = NULL;
	return 0;
}

UnitFileState
unit_get_unit_file_state(Unit *u)
{
	int r;

	assert(u);

	if (u->unit_file_state < 0 && u->fragment_path) {
		r = unit_file_get_state(u->manager->running_as ==
					SYSTEMD_SYSTEM ?
				      UNIT_FILE_SYSTEM :
				      UNIT_FILE_USER,
			NULL, lsb_basename(u->fragment_path),
			&u->unit_file_state);
		if (r < 0)
			u->unit_file_state = UNIT_FILE_BAD;
	}

	return u->unit_file_state;
}

int
unit_get_unit_file_preset(Unit *u)
{
	assert(u);

	if (u->unit_file_preset < 0 && u->fragment_path)
		u->unit_file_preset = unit_file_query_preset(
			u->manager->running_as == SYSTEMD_SYSTEM ?
				      UNIT_FILE_SYSTEM :
				      UNIT_FILE_USER,
			NULL, lsb_basename(u->fragment_path));

	return u->unit_file_preset;
}

Unit *
unit_ref_set(UnitRef *ref, Unit *source, Unit *target)
{
	assert(ref);
	assert(source);
	assert(target);

	if (ref->target)
		unit_ref_unset(ref);

	ref->source = source;
	ref->target = target;
	IWLIST_PREPEND(refs_by_target, target->refs_by_target, ref);
	return target;
}

void
unit_ref_unset(UnitRef *ref)
{
	assert(ref);

	if (!ref->target)
		return;

	/* We are about to drop a reference to the unit, make sure the garbage collection has a look at it as it might
         * be unreferenced now. */
	unit_add_to_gc_queue(ref->target);

	IWLIST_REMOVE(refs_by_target, ref->target->refs_by_target, ref);
	ref->source = ref->target = NULL;
}

int
unit_patch_contexts(Unit *u)
{
	CGroupContext *cc;
	ExecContext *ec;
	unsigned i;
	int r;

	assert(u);

	/* Patch in the manager defaults into the exec and cgroup
         * contexts, _after_ the rest of the settings have been
         * initialized */

	ec = unit_get_exec_context(u);
	if (ec) {
		/* This only copies in the ones that need memory */
		for (i = 0; i < RLIM_NLIMITS; i++)
			if (u->manager->rlimit[i] && !ec->rlimit[i]) {
				ec->rlimit[i] = newdup(struct rlimit,
					u->manager->rlimit[i], 1);
				if (!ec->rlimit[i])
					return -ENOMEM;
			}

		if (u->manager->running_as == SYSTEMD_USER &&
			!ec->working_directory) {
			r = get_home_dir(&ec->working_directory);
			if (r < 0)
				return r;

			/* Allow user services to run, even if the
                         * home directory is missing */
			ec->working_directory_missing_ok = true;
		}

		if (u->manager->running_as == SYSTEMD_USER &&
			(ec->syscall_whitelist ||
				!set_isempty(ec->syscall_filter) ||
				!set_isempty(ec->syscall_archs) ||
				ec->address_families_whitelist ||
				!set_isempty(ec->address_families)))
			ec->no_new_privileges = true;

#ifdef SVC_USE_libcap
		if (ec->private_devices)
			ec->capability_bounding_set &=
				~(UINT64_C(1) << CAP_MKNOD);
#endif
	}

	cc = unit_get_cgroup_context(u);
	if (cc) {
		if (ec && ec->private_devices &&
			cc->device_policy == CGROUP_AUTO)
			cc->device_policy = CGROUP_CLOSED;
	}

	return 0;
}

ExecContext *
unit_get_exec_context(Unit *u)
{
	size_t offset;
	assert(u);

	if (u->type < 0)
		return NULL;

	offset = UNIT_VTABLE(u)->exec_context_offset;
	if (offset <= 0)
		return NULL;

	return (ExecContext *)((uint8_t *)u + offset);
}

KillContext *
unit_get_kill_context(Unit *u)
{
	size_t offset;
	assert(u);

	if (u->type < 0)
		return NULL;

	offset = UNIT_VTABLE(u)->kill_context_offset;
	if (offset <= 0)
		return NULL;

	return (KillContext *)((uint8_t *)u + offset);
}

CGroupContext *
unit_get_cgroup_context(Unit *u)
{
	size_t offset;

	if (u->type < 0)
		return NULL;

	offset = UNIT_VTABLE(u)->cgroup_context_offset;
	if (offset <= 0)
		return NULL;

	return (CGroupContext *)((uint8_t *)u + offset);
}

ExecRuntime *
unit_get_exec_runtime(Unit *u)
{
	size_t offset;

	if (u->type < 0)
		return NULL;

	offset = UNIT_VTABLE(u)->exec_runtime_offset;
	if (offset <= 0)
		return NULL;

	return *(ExecRuntime **)((uint8_t *)u + offset);
}

static int
unit_drop_in_dir(Unit *u, UnitSetPropertiesMode mode, bool transient,
	char **dir)
{
	if (u->manager->running_as == SYSTEMD_USER) {
		int r;

		if (mode == UNIT_PERSISTENT && !transient)
			r = user_config_home(dir);
		else
			r = user_runtime_dir(dir);

		if (r == 0)
			return -ENOENT;
		return r;
	}

	if (mode == UNIT_PERSISTENT && !transient)
		*dir = strdup(SVC_PKGSYSCONFDIR "/system");
	else
		*dir = strdup(SVC_PKGRUNSTATEDIR "/system");
	if (!*dir)
		return -ENOMEM;

	return 0;
}

static int
unit_drop_in_file(Unit *u, UnitSetPropertiesMode mode, const char *name,
	char **p, char **q)
{
	_cleanup_free_ char *dir = NULL;
	int r;

	assert(u);

	r = unit_drop_in_dir(u, mode, u->transient, &dir);
	if (r < 0)
		return r;

	return drop_in_file(dir, u->id, 50, name, p, q);
}

int
unit_write_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name,
	const char *data)
{
	_cleanup_free_ char *dir = NULL, *p = NULL, *q = NULL;
	int r;

	assert(u);

	if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
		return 0;

	r = unit_drop_in_dir(u, mode, u->transient, &dir);
	if (r < 0)
		return r;

	r = write_drop_in(dir, u->id, 50, name, data);
	if (r < 0)
		return r;

	r = drop_in_file(dir, u->id, 50, name, &p, &q);
	if (r < 0)
		return r;

	r = strv_extend(&u->dropin_paths, q);
	if (r < 0)
		return r;

	strv_sort(u->dropin_paths);
	strv_uniq(u->dropin_paths);

	u->dropin_mtime = now(CLOCK_REALTIME);

	return 0;
}

int
unit_write_drop_in_format(Unit *u, UnitSetPropertiesMode mode, const char *name,
	const char *format, ...)
{
	_cleanup_free_ char *p = NULL;
	va_list ap;
	int r;

	assert(u);
	assert(name);
	assert(format);

	if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
		return 0;

	va_start(ap, format);
	r = vasprintf(&p, format, ap);
	va_end(ap);

	if (r < 0)
		return -ENOMEM;

	return unit_write_drop_in(u, mode, name, p);
}

int
unit_write_drop_in_private(Unit *u, UnitSetPropertiesMode mode,
	const char *name, const char *data)
{
	_cleanup_free_ char *ndata = NULL;

	assert(u);
	assert(name);
	assert(data);

	if (!UNIT_VTABLE(u)->private_section)
		return -EINVAL;

	if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
		return 0;

	ndata = strjoin("[", UNIT_VTABLE(u)->private_section, "]\n", data,
		NULL);
	if (!ndata)
		return -ENOMEM;

	return unit_write_drop_in(u, mode, name, ndata);
}

int
unit_write_drop_in_private_format(Unit *u, UnitSetPropertiesMode mode,
	const char *name, const char *format, ...)
{
	_cleanup_free_ char *p = NULL;
	va_list ap;
	int r;

	assert(u);
	assert(name);
	assert(format);

	if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
		return 0;

	va_start(ap, format);
	r = vasprintf(&p, format, ap);
	va_end(ap);

	if (r < 0)
		return -ENOMEM;

	return unit_write_drop_in_private(u, mode, name, p);
}

int
unit_remove_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name)
{
	_cleanup_free_ char *p = NULL, *q = NULL;
	int r;

	assert(u);

	if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
		return 0;

	r = unit_drop_in_file(u, mode, name, &p, &q);
	if (r < 0)
		return r;

	if (unlink(q) < 0)
		r = errno == ENOENT ? 0 : -errno;
	else
		r = 1;

	rmdir(p);
	return r;
}

int
unit_make_transient(Unit *u)
{
	int r;

	assert(u);

	u->load_state = UNIT_STUB;
	u->load_error = 0;
	u->transient = true;

	free(u->fragment_path);
	u->fragment_path = NULL;

	if (u->manager->running_as == SYSTEMD_USER) {
		_cleanup_free_ char *c = NULL;

		r = user_runtime_dir(&c);
		if (r < 0)
			return r;
		if (r == 0)
			return -ENOENT;

		u->fragment_path = strjoin(c, "/", u->id, NULL);
		if (!u->fragment_path)
			return -ENOMEM;

		mkdir_p(c, 0755);
	} else {
		u->fragment_path =
			strappend(SVC_PKGRUNSTATEDIR "/system/", u->id);
		if (!u->fragment_path)
			return -ENOMEM;

		mkdir_p(SVC_PKGRUNSTATEDIR "/system", 0755);
	}

	return write_string_file_atomic_label(u->fragment_path,
		"# Transient stub");
}

int
unit_kill_context(Unit *u, KillContext *c, KillOperation k, pid_t main_pid,
	pid_t control_pid, bool main_pid_alien)
{
	int sig, wait_for_exit = false, r;

	assert(u);
	assert(c);

	if (c->kill_mode == KILL_NONE)
		return 0;

	switch (k) {
	case KILL_KILL:
		sig = SIGKILL;
		break;
	case KILL_ABORT:
		sig = SIGABRT;
		break;
	case KILL_TERMINATE:
		sig = c->kill_signal;
		break;
	default:
		assert_not_reached();
	}

	if (main_pid > 0) {
		r = kill_and_sigcont(main_pid, sig);

		if (r < 0 && r != -ESRCH) {
			_cleanup_free_ char *comm = NULL;
			get_process_comm(main_pid, &comm);

			log_unit_warning_errno(u->id, r,
				"Failed to kill main process " PID_FMT
				" (%s): %m",
				main_pid, strna(comm));
		} else {
			if (!main_pid_alien)
				wait_for_exit = true;

			if (c->send_sighup && k != KILL_KILL)
				kill(main_pid, SIGHUP);
		}
	}

	if (control_pid > 0) {
		r = kill_and_sigcont(control_pid, sig);

		if (r < 0 && r != -ESRCH) {
			_cleanup_free_ char *comm = NULL;
			get_process_comm(control_pid, &comm);

			log_unit_warning_errno(u->id, r,
				"Failed to kill control process " PID_FMT
				" (%s): %m",
				control_pid, strna(comm));
		} else {
			wait_for_exit = true;

			if (c->send_sighup && k != KILL_KILL)
				kill(control_pid, SIGHUP);
		}
	}

	if ((c->kill_mode == KILL_CONTROL_GROUP ||
		    (c->kill_mode == KILL_MIXED && k == KILL_KILL)) &&
		u->cgroup_path) {
		_cleanup_set_free_ Set *pid_set = NULL;

		/* Exclude the main/control pids from being killed via the cgroup */
		pid_set = unit_pid_set(main_pid, control_pid);
		if (!pid_set)
			return -ENOMEM;

		r = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path,
			sig, true, true, false, pid_set);
		if (r < 0) {
			if (r != -EAGAIN && r != -ESRCH && r != -ENOENT)
				log_unit_warning_errno(u->id, r,
					"Failed to kill control group: %m");
		} else if (r > 0) {
			wait_for_exit = true;

			if (c->send_sighup && k != KILL_KILL) {
				set_free(pid_set);

				pid_set = unit_pid_set(main_pid, control_pid);
				if (!pid_set)
					return -ENOMEM;

				cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER,
					u->cgroup_path, SIGHUP, false, true,
					false, pid_set);
			}
		}
	}

	return wait_for_exit;
}

int
unit_require_mounts_for(Unit *u, const char *path)
{
	char prefix[strlen(path) + 1], *p;
	int r;

	assert(u);
	assert(path);

	/* Registers a unit for requiring a certain path and all its
         * prefixes. We keep a simple array of these paths in the
         * unit, since its usually short. However, we build a prefix
         * table for all possible prefixes so that new appearing mount
         * units can easily determine which units to make themselves a
         * dependency of. */

	if (!path_is_absolute(path))
		return -EINVAL;

	p = strdup(path);
	if (!p)
		return -ENOMEM;

	path_kill_slashes(p);

	if (!path_is_safe(p)) {
		free(p);
		return -EPERM;
	}

	if (strv_contains(u->requires_mounts_for, p)) {
		free(p);
		return 0;
	}

	r = strv_consume(&u->requires_mounts_for, p);
	if (r < 0)
		return r;

	PATH_FOREACH_PREFIX_MORE (prefix, p) {
		Set *x;

		x = hashmap_get(u->manager->units_requiring_mounts_for, prefix);
		if (!x) {
			char *q;

			if (!u->manager->units_requiring_mounts_for) {
				u->manager->units_requiring_mounts_for =
					hashmap_new(&string_hash_ops);
				if (!u->manager->units_requiring_mounts_for)
					return -ENOMEM;
			}

			q = strdup(prefix);
			if (!q)
				return -ENOMEM;

			x = set_new(NULL);
			if (!x) {
				free(q);
				return -ENOMEM;
			}

			r = hashmap_put(u->manager->units_requiring_mounts_for,
				q, x);
			if (r < 0) {
				free(q);
				set_free(x);
				return r;
			}
		}

		r = set_put(x, u);
		if (r < 0)
			return r;
	}

	return 0;
}

int
unit_setup_exec_runtime(Unit *u)
{
	ExecRuntime **rt;
	size_t offset;
	Iterator i;
	Unit *other;

	offset = UNIT_VTABLE(u)->exec_runtime_offset;
	assert(offset > 0);

	/* Check if there already is an ExecRuntime for this unit? */
	rt = (ExecRuntime **)((uint8_t *)u + offset);
	if (*rt)
		return 0;

	/* Try to get it from somebody else */
	SET_FOREACH (other, u->dependencies[UNIT_JOINS_NAMESPACE_OF], i) {
		*rt = unit_get_exec_runtime(other);
		if (*rt) {
			exec_runtime_ref(*rt);
			return 0;
		}
	}

	return exec_runtime_make(rt, unit_get_exec_context(u), u->id);
}

pid_t
unit_control_pid(Unit *u)
{
	assert(u);

	if (UNIT_VTABLE(u)->control_pid)
		return UNIT_VTABLE(u)->control_pid(u);

	return 0;
}

pid_t
unit_main_pid(Unit *u)
{
	assert(u);

	if (UNIT_VTABLE(u)->main_pid)
		return UNIT_VTABLE(u)->main_pid(u);

	return 0;
}

bool
unit_needs_console(Unit *u)
{
	ExecContext *ec;
	UnitActiveState state;

	assert(u);

	state = unit_active_state(u);

	if (UNIT_IS_INACTIVE_OR_FAILED(state))
		return false;

	if (UNIT_VTABLE(u)->needs_console)
		return UNIT_VTABLE(u)->needs_console(u);

	/* If this unit type doesn't implement this call, let's use a generic fallback implementation: */
	ec = unit_get_exec_context(u);
	if (!ec)
		return false;

	return exec_context_may_touch_console(ec);
}

static const char *const unit_active_state_table[_UNIT_ACTIVE_STATE_MAX] = {
	[UNIT_ACTIVE] = "active",
	[UNIT_RELOADING] = "reloading",
	[UNIT_INACTIVE] = "inactive",
	[UNIT_FAILED] = "failed",
	[UNIT_ACTIVATING] = "activating",
	[UNIT_DEACTIVATING] = "deactivating"
};

DEFINE_STRING_TABLE_LOOKUP(unit_active_state, UnitActiveState);

static const char *const collect_mode_table[_COLLECT_MODE_MAX] = {
	[COLLECT_INACTIVE] = "inactive",
	[COLLECT_INACTIVE_OR_FAILED] = "inactive-or-failed",
};

DEFINE_STRING_TABLE_LOOKUP(collect_mode, CollectMode);
