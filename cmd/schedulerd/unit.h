#pragma once

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

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct Unit Unit;
typedef struct UnitVTable UnitVTable;
typedef enum UnitActiveState UnitActiveState;
typedef struct UnitRef UnitRef;
typedef struct UnitStatusMessageFormats UnitStatusMessageFormats;

#include "cgroup.h"
#include "condition.h"
#include "emergency-action.h"
#include "execute.h"
#include "install.h"
#include "list.h"
#include "sd-event.h"
#include "set.h"
#include "socket-util.h"
#include "unit-name.h"
#include "util.h"

enum UnitActiveState {
	UNIT_ACTIVE,
	UNIT_RELOADING,
	UNIT_INACTIVE,
	UNIT_FAILED,
	UNIT_ACTIVATING,
	UNIT_DEACTIVATING,
	_UNIT_ACTIVE_STATE_MAX,
	_UNIT_ACTIVE_STATE_INVALID = -1
};

typedef enum KillOperation {
	KILL_TERMINATE,
	KILL_KILL,
	KILL_ABORT,
} KillOperation;

typedef enum CollectMode {
	COLLECT_INACTIVE,
	COLLECT_INACTIVE_OR_FAILED,
	_COLLECT_MODE_MAX,
	_COLLECT_MODE_INVALID = -1,
} CollectMode;

static inline bool
UNIT_IS_ACTIVE_OR_RELOADING(UnitActiveState t)
{
	return t == UNIT_ACTIVE || t == UNIT_RELOADING;
}

static inline bool
UNIT_IS_ACTIVE_OR_ACTIVATING(UnitActiveState t)
{
	return t == UNIT_ACTIVE || t == UNIT_ACTIVATING || t == UNIT_RELOADING;
}

static inline bool
UNIT_IS_INACTIVE_OR_DEACTIVATING(UnitActiveState t)
{
	return t == UNIT_INACTIVE || t == UNIT_FAILED || t == UNIT_DEACTIVATING;
}

static inline bool
UNIT_IS_INACTIVE_OR_FAILED(UnitActiveState t)
{
	return t == UNIT_INACTIVE || t == UNIT_FAILED;
}

#include "job.h"
#include "manager.h"

struct UnitRef {
	/* Keeps tracks of references to a unit. This is useful so
         * that we can merge two units if necessary and correct all
         * references to them */

	Unit *source, *target;
	LIST_FIELDS(UnitRef, refs_by_target);
};

struct Unit {
	Manager *manager;

	UnitType type;
	UnitLoadState load_state;
	Unit *merged_into;

	char *id; /* One name is special because we use it for identification. Points to an entry in the names set */
	char *instance;

	Set *names;
	Set *dependencies[_UNIT_DEPENDENCY_MAX];

	char **requires_mounts_for;

	char *description;
	char **documentation;

	char *fragment_path; /* if loaded from a config file this is the primary path to it */
	char *source_path; /* if converted, the source file */
	char **dropin_paths;
	usec_t fragment_mtime;
	usec_t source_mtime;
	usec_t dropin_mtime;

	/* If there is something to do with this unit, then this is the installed job for it */
	Job *job;

	/* JOB_NOP jobs are special and can be installed without disturbing the real job. */
	Job *nop_job;

	/* The slot used for watching NameOwnerChanged signals */
  sd_bus_slot *match_bus_slot;
	sd_bus_slot *get_name_owner_slot;

	/* Job timeout and action to take */
	usec_t job_timeout;
	EmergencyAction job_timeout_action;
	char *job_timeout_reboot_arg;

	/* References to this unit from clients */
  sd_bus_track *bus_track;
	char **deserialized_refs;

	/* References to this */
	LIST_HEAD(UnitRef, refs_by_target);

	/* Conditions to check */
	LIST_HEAD(Condition, conditions);
	LIST_HEAD(Condition, asserts);

	dual_timestamp condition_timestamp;
	dual_timestamp assert_timestamp;

	dual_timestamp inactive_exit_timestamp;
	dual_timestamp active_enter_timestamp;
	dual_timestamp active_exit_timestamp;
	dual_timestamp inactive_enter_timestamp;

	UnitRef slice;

	/* Per type list */
	LIST_FIELDS(Unit, units_by_type);

	/* All units which have requires_mounts_for set */
	LIST_FIELDS(Unit, has_requires_mounts_for);

	/* Load queue */
	LIST_FIELDS(Unit, load_queue);

	/* D-Bus queue */
	LIST_FIELDS(Unit, dbus_queue);

	/* Cleanup queue */
	LIST_FIELDS(Unit, cleanup_queue);

	/* GC queue */
	LIST_FIELDS(Unit, gc_queue);

	/* CGroup realize members queue */
	LIST_FIELDS(Unit, cgroup_queue);

	/* Target dependencies queue */
	LIST_FIELDS(Unit, target_deps_queue);

	/* Queue of units with StopWhenUnneeded set that shell be checked for clean-up. */
	LIST_FIELDS(Unit, stop_when_unneeded_queue);

	/* PIDs we keep an eye on. Note that a unit might have many
         * more, but these are the ones we care enough about to
         * process SIGCHLD for */
	Set *pids;

	/* Used in sigchld event invocation to avoid repeat events being invoked */
	uint64_t sigchldgen;

	/* Used during GC sweeps */
	unsigned gc_marker;

	/* When deserializing, temporarily store the job type for this
         * unit here, if there was a job scheduled.
         * Only for deserializing from a legacy version. New style uses full
         * serialized jobs. */
	int deserialized_job; /* This is actually of type JobType */

	/* Error code when we didn't manage to load the unit (negative) */
	int load_error;

	/* Make sure we never enter endless loops with the check unneeded logic */
	RateLimit check_unneeded_ratelimit;

	/* Cached unit file state and preset */
	UnitFileState unit_file_state;
	int unit_file_preset;

	/* Counterparts in the cgroup filesystem */
	char *cgroup_path;
	CGroupMask cgroup_realized_mask;
	CGroupMask cgroup_subtree_mask;
	CGroupMask cgroup_members_mask;

	/* How to start OnFailure units */
	JobMode on_failure_job_mode;

	/* Tweaking the GC logic */
	CollectMode collect_mode;

	/* Garbage collect us we nobody wants or requires us anymore */
	bool stop_when_unneeded;

	/* Create default dependencies */
	bool default_dependencies;

	/* Refuse manual starting, allow starting only indirectly via dependency. */
	bool refuse_manual_start;

	/* Don't allow the user to stop this unit manually, allow stopping only indirectly via dependency. */
	bool refuse_manual_stop;

	/* Allow isolation requests */
	bool allow_isolate;

	/* Ignore this unit when isolating */
	bool ignore_on_isolate;

	/* Ignore this unit when snapshotting */
	bool ignore_on_snapshot;

	/* Did the last condition check succeed? */
	bool condition_result;
	bool assert_result;

	/* Is this a transient unit? */
	bool transient;

	bool in_load_queue: 1;
	bool in_dbus_queue: 1;
	bool in_cleanup_queue: 1;
	bool in_gc_queue: 1;
	bool in_cgroup_queue: 1;
	bool in_target_deps_queue: 1;
	bool in_stop_when_unneeded_queue: 1;

	bool sent_dbus_new_signal: 1;

	bool no_gc: 1;

	bool in_audit: 1;
	bool on_console: 1;

	bool cgroup_realized: 1;
	bool cgroup_members_mask_valid: 1;
	bool cgroup_subtree_mask_valid: 1;

	/* For transient units: whether to add a bus track reference after creating the unit */
  bool bus_track_add:1;
};

struct UnitStatusMessageFormats {
	const char *starting_stopping[2];
	const char *finished_start_job[_JOB_RESULT_MAX];
	const char *finished_stop_job[_JOB_RESULT_MAX];
};

typedef enum UnitWriteFlags {
        /* Write a runtime unit file or drop-in (i.e. one below /run) */
        UNIT_RUNTIME                = 1 << 0,

        /* Write a persistent drop-in (i.e. one below /etc) */
        UNIT_PERSISTENT             = 1 << 1,

        /* Place this item in the per-unit-type private section, instead of [Unit] */
        UNIT_PRIVATE                = 1 << 2,

        /* Apply specifier escaping */
        UNIT_ESCAPE_SPECIFIERS      = 1 << 3,

        /* Escape elements of ExecStart= syntax, incl. prevention of variable expansion */
        UNIT_ESCAPE_EXEC_SYNTAX_ENV = 1 << 4,

        /* Escape elements of ExecStart=: syntax (no variable expansion) */
        UNIT_ESCAPE_EXEC_SYNTAX     = 1 << 5,

        /* Apply C escaping before writing */
        UNIT_ESCAPE_C               = 1 << 6,
} UnitWriteFlags;

typedef enum UnitSetPropertiesMode {
	UNIT_CHECK = 0,
	UNIT_RUNTIME_OLD = 1,
	UNIT_PERSISTENT_OLD = 2,
} UnitSetPropertiesMode;

typedef struct ActivationDetails {
        unsigned n_ref;
        UnitType trigger_unit_type;
        char *trigger_unit_name;
} ActivationDetails;

int activation_details_append_pair(ActivationDetails *info, char ***strv);

#ifdef SVC_USE_Automount
#include "automount.h"
#endif
#ifdef SVC_USE_Device
#include "device.h"
#endif
#ifdef SVC_USE_MOUNT
#include "mount.h"
#endif
#include "path.h"
#include "scope.h"
#include "service.h"
#include "slice.h"
#include "snapshot.h"
#include "socket.h"
#ifdef SVC_USE_Swap
#include "swap.h"
#endif
#include "target.h"
#include "timer.h"

struct UnitVTable {
	/* How much memory does an object of this unit type need */
	size_t object_size;

	/* If greater than 0, the offset into the object where
         * ExecContext is found, if the unit type has that */
	size_t exec_context_offset;

	/* If greater than 0, the offset into the object where
         * CGroupContext is found, if the unit type has that */
	size_t cgroup_context_offset;

	/* If greater than 0, the offset into the object where
         * KillContext is found, if the unit type has that */
	size_t kill_context_offset;

	/* If greater than 0, the offset into the object where the
         * pointer to ExecRuntime is found, if the unit type has
         * that */
	size_t exec_runtime_offset;

	/* The name of the configuration file section with the private settings of this unit */
	const char *private_section;

	/* Config file sections this unit type understands, separated
         * by NUL chars */
	const char *sections;

	/* This should reset all type-specific variables. This should
         * not allocate memory, and is called with zero-initialized
         * data. It should hence only initialize variables that need
         * to be set != 0. */
	void (*init)(Unit *u);

	/* This should free all type-specific variables. It should be
         * idempotent. */
	void (*done)(Unit *u);

	/* Actually load data from disk. This may fail, and should set
         * load_state to UNIT_LOADED, UNIT_MERGED or leave it at
         * UNIT_STUB if no configuration could be found. */
	int (*load)(Unit *u);

	/* If a lot of units got created via enumerate(), this is
         * where to actually set the state and call unit_notify().
         *
         * This must not reference other units (maybe implicitly through spawning
         * jobs), because it is possible that they are not yet coldplugged.
         * Such actions must be deferred until the end of coldplug bу adding
         * a "Unit* -> int(*)(Unit*)" entry into the hashmap.
         */
	int (*coldplug)(Unit *u, Hashmap *deferred_work);

	void (*dump)(Unit *u, FILE *f, const char *prefix);

	int (*start)(Unit *u);
	int (*stop)(Unit *u);
	int (*reload)(Unit *u);

	int (*kill)(Unit *u, KillWho w, int signo, sd_bus_error *error);

	bool (*can_reload)(Unit *u);

	/* Write all data that cannot be restored from other sources
         * away using unit_serialize_item() */
	int (*serialize)(Unit *u, FILE *f, FDSet *fds);

	/* Restore one item from the serialization */
	int (*deserialize_item)(Unit *u, const char *key, const char *data,
		FDSet *fds);

	/* Try to match up fds with what we need for this unit */
	int (*distribute_fds)(Unit *u, FDSet *fds);

	/* Boils down the more complex internal state of this unit to
         * a simpler one that the engine can understand */
	UnitActiveState (*active_state)(Unit *u);

	/* Returns the substate specific to this unit type as
         * string. This is purely information so that we can give the
         * user a more fine grained explanation in which actual state a
         * unit is in. */
	const char *(*sub_state_to_string)(Unit *u);

	/* Return false when there is a reason to prevent this unit from being gc'ed
         * even though nothing references it and it isn't active in any way. */
	bool (*may_gc)(Unit *u);

	/* When the unit is not running and no job for it queued we shall release its runtime resources */
	void (*release_resources)(Unit *u);

	/* Return true when this unit is suitable for snapshotting */
	bool (*check_snapshot)(Unit *u);

	/* Invoked on every child that died */
	void (*sigchld_event)(Unit *u, pid_t pid, int code, int status);

	/* Reset failed state if we are in failed state */
	void (*reset_failed)(Unit *u);

	/* Called whenever any of the cgroups this unit watches for
         * ran empty */
	void (*notify_cgroup_empty)(Unit *u);

	/* Called whenever a process of this unit sends us a message */
	void (*notify_message)(Unit *u, const struct socket_ucred *ucred,
		char **tags, FDSet *fds);

	/* Called whenever a name this Unit registered for comes or
         * goes away. */
	void (*bus_name_owner_change)(Unit *u, const char *name,
		const char *old_owner, const char *new_owner);

	/* Called for each property that is being set */
	int (*bus_set_property)(Unit *u, const char *name,
		sd_bus_message *message, UnitSetPropertiesMode mode,
		sd_bus_error *error);

	/* Called after at least one property got changed to apply the necessary change */
	int (*bus_commit_properties)(Unit *u);

	/* Return the unit this unit is following */
	Unit *(*following)(Unit *u);

	/* Return the set of units that are following each other */
	int (*following_set)(Unit *u, Set **s);

	/* Invoked each time a unit this unit is triggering changes
         * state or gains/loses a job */
	void (*trigger_notify)(Unit *u, Unit *trigger);

	/* Called whenever CLOCK_REALTIME made a jump */
	void (*time_change)(Unit *u);

	int (*get_timeout)(Unit *u, uint64_t *timeout);

	/* Returns the main PID if there is any defined, or 0. */
	pid_t (*main_pid)(Unit *u);

	/* Returns the main PID if there is any defined, or 0. */
	pid_t (*control_pid)(Unit *u);

	/* Returns true if the unit currently needs access to the console */
	bool (*needs_console)(Unit *u);

	/* This is called for each unit type and should be used to
         * enumerate existing devices and load them. However,
         * everything that is loaded here should still stay in
         * inactive state. It is the job of the coldplug() call above
         * to put the units into the initial state.  */
	int (*enumerate)(Manager *m);

	/* Type specific cleanups. */
	void (*shutdown)(Manager *m);

	/* If this function is set and return false all jobs for units
         * of this type will immediately fail. */
	bool (*supported)(Manager *m);

	/* The interface name */
	const char *bus_interface;

	/* The bus vtable */
	const sd_bus_vtable *bus_vtable;

	/* The strings to print in status messages */
	UnitStatusMessageFormats status_message_formats;

	/* Can units of this type have multiple names? */
	bool no_alias: 1;

	/* Instances make no sense for this type */
	bool no_instances: 1;

	/* Exclude from automatic gc */
	bool no_gc: 1;

	/* True if transient units of this type are OK */
	bool can_transient: 1;
};

extern const UnitVTable *const unit_vtable[_UNIT_TYPE_MAX];

#define UNIT_VTABLE(u) unit_vtable[(u)->type]

/* For casting a unit into the various unit types */
#define DEFINE_CAST(UPPERCASE, MixedCase)                                      \
	static inline MixedCase *UPPERCASE(Unit *u)                            \
	{                                                                      \
		if (_unlikely_(!u || u->type != UNIT_##UPPERCASE))             \
			return NULL;                                           \
                                                                               \
		return (MixedCase *)u;                                         \
	}

/* For casting the various unit types into a unit */
#define UNIT(u) (&(u)->meta)

#define UNIT_TRIGGER(u) ((Unit *)set_first((u)->dependencies[UNIT_TRIGGERS]))

DEFINE_CAST(SERVICE, Service);
DEFINE_CAST(SOCKET, Socket);
DEFINE_CAST(TARGET, Target);
DEFINE_CAST(SNAPSHOT, Snapshot);
#ifdef SVC_USE_Device
DEFINE_CAST(DEVICE, Device);
#endif
#ifdef SVC_USE_Mount
DEFINE_CAST(MOUNT, Mount);
#endif
#ifdef SVC_USE_Automount
DEFINE_CAST(AUTOMOUNT, Automount);
#endif
#ifdef SVC_USE_Swap
DEFINE_CAST(SWAP, Swap);
#endif
DEFINE_CAST(TIMER, Timer);
DEFINE_CAST(PATH, Path);
DEFINE_CAST(SLICE, Slice);
DEFINE_CAST(SCOPE, Scope);

Unit *unit_new(Manager *m, size_t size);
void unit_free(Unit *u);

int unit_add_name(Unit *u, const char *name);

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other,
	bool add_reference);
int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e,
	Unit *other, bool add_reference);

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name,
	const char *filename, bool add_reference);
int unit_add_two_dependencies_by_name(Unit *u, UnitDependency d,
	UnitDependency e, const char *name, const char *path,
	bool add_reference);

int unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d,
	const char *name, const char *filename, bool add_reference);
int unit_add_two_dependencies_by_name_inverse(Unit *u, UnitDependency d,
	UnitDependency e, const char *name, const char *path,
	bool add_reference);

int unit_add_exec_dependencies(Unit *u, ExecContext *c);

int unit_choose_id(Unit *u, const char *name);
int unit_set_description(Unit *u, const char *description);

bool unit_may_gc(Unit *u);

void unit_add_to_load_queue(Unit *u);
void unit_add_to_dbus_queue(Unit *u);
void unit_add_to_cleanup_queue(Unit *u);
void unit_add_to_gc_queue(Unit *u);
void unit_add_to_target_deps_queue(Unit *u);
void unit_add_to_stop_when_unneeded_queue(Unit *u);

int unit_merge(Unit *u, Unit *other);
int unit_merge_by_name(Unit *u, const char *other);

Unit *unit_follow_merge(Unit *u) _pure_;

int unit_load_fragment_and_dropin(Unit *u);
int unit_load_fragment_and_dropin_optional(Unit *u);
int unit_load(Unit *unit);

int unit_add_default_slice(Unit *u, CGroupContext *c);

const char *unit_description(Unit *u) _pure_;

bool unit_has_name(Unit *u, const char *name);

UnitActiveState unit_active_state(Unit *u);

const char *unit_sub_state_to_string(Unit *u);

void unit_dump(Unit *u, FILE *f, const char *prefix);

bool unit_can_reload(Unit *u) _pure_;
bool unit_can_start(Unit *u) _pure_;
bool unit_can_isolate(Unit *u) _pure_;

int unit_start(Unit *u);
int unit_stop(Unit *u);
int unit_reload(Unit *u);

int unit_kill(Unit *u, KillWho w, int signo, int code, int value, sd_bus_error *ret_error);
int unit_kill_common(Unit *u, KillWho who, int signo, pid_t main_pid,
	pid_t control_pid, sd_bus_error *error);

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns,
	bool reload_success);

int unit_watch_pid(Unit *u, pid_t pid, bool exclusive);
void unit_unwatch_pid(Unit *u, pid_t pid);
int unit_watch_all_pids(Unit *u);
void unit_unwatch_all_pids(Unit *u);

void unit_tidy_watch_pids(Unit *u, pid_t except1, pid_t except2);

int unit_install_bus_match(Unit *u, sd_bus *bus, const char *name);
int unit_watch_bus_name(Unit *u, const char *name);
void unit_unwatch_bus_name(Unit *u, const char *name);

bool unit_job_is_applicable(Unit *u, JobType j);

int set_unit_path(const char *p);

char *unit_dbus_path(Unit *u);

int unit_load_related_unit(Unit *u, const char *type, Unit **_found);

bool unit_can_serialize(Unit *u) _pure_;
int unit_serialize(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs);
void unit_serialize_item_format(Unit *u, FILE *f, const char *key,
	const char *value, ...) _printf_(4, 5);
void unit_serialize_item(Unit *u, FILE *f, const char *key, const char *value);
int unit_deserialize(Unit *u, FILE *f, FDSet *fds);

int unit_add_node_link(Unit *u, const char *what, bool wants, UnitDependency d);

int unit_coldplug(Unit *u, Hashmap *deferred_work);

void unit_status_printf(Unit *u, const char *status,
	const char *unit_status_msg_format) _printf_(3, 0);
void unit_status_emit_starting_stopping_reloading(Unit *u, JobType t);

bool unit_need_daemon_reload(Unit *u);

void unit_reset_failed(Unit *u);

Unit *unit_following(Unit *u);
int unit_following_set(Unit *u, Set **s);

const char *unit_slice_name(Unit *u);

bool unit_stop_pending(Unit *u) _pure_;
bool unit_inactive_or_pending(Unit *u) _pure_;
bool unit_active_or_pending(Unit *u);

int unit_add_default_target_dependency(Unit *u, Unit *target);

char *unit_default_cgroup_path(Unit *u);

void unit_start_on_failure(Unit *u);
void unit_trigger_notify(Unit *u);

UnitFileState unit_get_unit_file_state(Unit *u);
int unit_get_unit_file_preset(Unit *u);

Unit *unit_ref_set(UnitRef *ref, Unit *source, Unit *target);
void unit_ref_unset(UnitRef *ref);

#define UNIT_DEREF(ref) ((ref).target)
#define UNIT_ISSET(ref) (!!(ref).target)

int unit_patch_contexts(Unit *u);

ExecContext *unit_get_exec_context(Unit *u) _pure_;
KillContext *unit_get_kill_context(Unit *u) _pure_;
CGroupContext *unit_get_cgroup_context(Unit *u) _pure_;

ExecRuntime *unit_get_exec_runtime(Unit *u) _pure_;

int unit_setup_exec_runtime(Unit *u);

int unit_write_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name,
	const char *data);
int unit_write_drop_in_format(Unit *u, UnitSetPropertiesMode mode,
	const char *name, const char *format, ...) _printf_(4, 5);

int unit_write_drop_in_private(Unit *u, UnitSetPropertiesMode mode,
	const char *name, const char *data);
int unit_write_drop_in_private_format(Unit *u, UnitSetPropertiesMode mode,
	const char *name, const char *format, ...) _printf_(4, 5);

int unit_remove_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name);

int unit_kill_context(Unit *u, KillContext *c, KillOperation k, pid_t main_pid,
	pid_t control_pid, bool main_pid_alien);

int unit_make_transient(Unit *u);

int unit_require_mounts_for(Unit *u, const char *path);

bool unit_is_pristine(Unit *u);

bool unit_is_unneeded(Unit *u);

pid_t unit_control_pid(Unit *u);
pid_t unit_main_pid(Unit *u);

const char *unit_active_state_to_string(UnitActiveState i) _const_;
UnitActiveState unit_active_state_from_string(const char *s) _pure_;

const char *collect_mode_to_string(CollectMode m) _const_;
CollectMode collect_mode_from_string(const char *s) _pure_;

bool unit_needs_console(Unit *u);

/* Macros which append UNIT= or USER_UNIT= to the message */

#define log_unit_full_errno(unit, level, error, ...)                           \
	log_object_internal(level, error, __FILE__, __LINE__, __func__,        \
		getpid() == 1 ? "UNIT=" : "USER_UNIT=", unit, __VA_ARGS__)
#define log_unit_full(unit, level, ...)                                        \
	log_unit_full_errno(unit, level, 0, __VA_ARGS__)

#define log_unit_debug(unit, ...) log_unit_full(unit, LOG_DEBUG, __VA_ARGS__)
#define log_unit_info(unit, ...) log_unit_full(unit, LOG_INFO, __VA_ARGS__)
#define log_unit_notice(unit, ...) log_unit_full(unit, LOG_NOTICE, __VA_ARGS__)
#define log_unit_warning(unit, ...)                                            \
	log_unit_full(unit, LOG_WARNING, __VA_ARGS__)
#define log_unit_error(unit, ...) log_unit_full(unit, LOG_ERR, __VA_ARGS__)

#define log_unit_debug_errno(unit, error, ...)                                 \
	log_unit_full_errno(unit, LOG_DEBUG, error, __VA_ARGS__)
#define log_unit_info_errno(unit, error, ...)                                  \
	log_unit_full_errno(unit, LOG_INFO, error, __VA_ARGS__)
#define log_unit_notice_errno(unit, error, ...)                                \
	log_unit_full_errno(unit, LOG_NOTICE, error, __VA_ARGS__)
#define log_unit_warning_errno(unit, error, ...)                               \
	log_unit_full_errno(unit, LOG_WARNING, error, __VA_ARGS__)
#define log_unit_error_errno(unit, error, ...)                                 \
	log_unit_full_errno(unit, LOG_ERR, error, __VA_ARGS__)

#define log_unit_struct(unit, level, ...)                                      \
	log_struct(level, getpid() == 1 ? "UNIT=%s" : "USER_UNIT=%s", unit,    \
		__VA_ARGS__)
#define log_unit_struct_errno(unit, level, error, ...)                         \
	log_struct_errno(level, error,                                         \
		getpid() == 1 ? "UNIT=%s" : "USER_UNIT=%s", unit, __VA_ARGS__)
