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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct Job Job;
typedef struct JobDependency JobDependency;
typedef enum JobType JobType;
typedef enum JobState JobState;
typedef enum JobMode JobMode;
typedef enum JobResult JobResult;

/* Be careful when changing the job types! Adjust job_merging_table[] accordingly! */
enum JobType {
	JOB_START, /* if a unit does not support being started, we'll just wait until it becomes active */
	JOB_VERIFY_ACTIVE,

	JOB_STOP,

	JOB_RELOAD, /* if running, reload */

	/* Note that restarts are first treated like JOB_STOP, but
         * then instead of finishing are patched to become
         * JOB_START. */
	JOB_RESTART, /* If running, stop. Then start unconditionally. */

	_JOB_TYPE_MAX_MERGING,

	/* JOB_NOP can enter into a transaction, but as it won't pull in
         * any dependencies and it uses the special 'nop_job' slot in Unit,
         * it won't have to merge with anything (except possibly into another
         * JOB_NOP, previously installed). JOB_NOP is special-cased in
         * job_type_is_*() functions so that the transaction can be
         * activated. */
	JOB_NOP = _JOB_TYPE_MAX_MERGING, /* do nothing */

	_JOB_TYPE_MAX_IN_TRANSACTION,

	/* JOB_TRY_RESTART can never appear in a transaction, because
         * it always collapses into JOB_RESTART or JOB_NOP before entering.
         * Thus we never need to merge it with anything. */
	JOB_TRY_RESTART =
		_JOB_TYPE_MAX_IN_TRANSACTION, /* if running, stop and then start */

	/* Similar to JOB_TRY_RESTART but collapses to JOB_RELOAD or JOB_NOP */
	JOB_TRY_RELOAD,

	/* JOB_RELOAD_OR_START won't enter into a transaction and cannot result
         * from transaction merging (there's no way for JOB_RELOAD and
         * JOB_START to meet in one transaction). It can result from a merge
         * during job installation, but then it will immediately collapse into
         * one of the two simpler types. */
	JOB_RELOAD_OR_START, /* if running, reload, otherwise start */

	_JOB_TYPE_MAX,
	_JOB_TYPE_INVALID = -1
};

enum JobState {
	JOB_WAITING,
	JOB_RUNNING,
	_JOB_STATE_MAX,
	_JOB_STATE_INVALID = -1
};

enum JobMode {
	JOB_FAIL, /* Fail if a conflicting job is already queued */
	JOB_REPLACE, /* Replace an existing conflicting job */
	JOB_REPLACE_IRREVERSIBLY, /* Like JOB_REPLACE + produce irreversible jobs */
	JOB_ISOLATE, /* Start a unit, and stop all others */
	JOB_FLUSH, /* Flush out all other queued jobs when queing this one */
	JOB_IGNORE_DEPENDENCIES, /* Ignore both requirement and ordering dependencies */
	JOB_IGNORE_REQUIREMENTS, /* Ignore requirement dependencies */
	_JOB_MODE_MAX,
	_JOB_MODE_INVALID = -1
};

enum JobResult {
	JOB_DONE, /* Job completed successfully */
	JOB_CANCELED, /* Job canceled by a conflicting job installation or by explicit cancel request */
	JOB_TIMEOUT, /* Job timeout elapsed */
	JOB_FAILED, /* Job failed */
	JOB_DEPENDENCY, /* A required dependency job did not result in JOB_DONE */
	JOB_SKIPPED, /* Negative result of JOB_VERIFY_ACTIVE */
	JOB_INVALID, /* JOB_RELOAD of inactive unit */
	JOB_ASSERT, /* Couldn't start a unit, because an assert didn't hold */
	JOB_UNSUPPORTED, /* Couldn't start a unit, because the unit type is not supported on the system */
	_JOB_RESULT_MAX,
	_JOB_RESULT_INVALID = -1
};

#include "hashmap.h"
#include "list.h"
#include "manager.h"
#include "sd-event.h"
#include "unit.h"

struct JobDependency {
	/* Encodes that the 'subject' job needs the 'object' job in
         * some way. This structure is used only while building a transaction. */
	Job *subject;
	Job *object;

	IWLIST_FIELDS(JobDependency, subject);
	IWLIST_FIELDS(JobDependency, object);

	bool matters;
	bool conflicts;
};

struct Job {
	Manager *manager;
	Unit *unit;

	IWLIST_FIELDS(Job, transaction); /* other jobs in the tx on same unit */
	IWLIST_FIELDS(Job, run_queue);
	IWLIST_FIELDS(Job, dbus_queue);

	IWLIST_HEAD(JobDependency, subject_list);
	IWLIST_HEAD(JobDependency, object_list);

	/* Used for graph algs as a "I have been here" marker */
	Job *marker;
	unsigned generation;

	uint32_t id;

	JobType type;
	JobState state;

	sd_event_source *timer_event_source;
	usec_t begin_usec;

	/*
         * This tracks where to send signals, and also which clients
         * are allowed to call DBus methods on the job (other than
         * root).
         *
         * There can be more than one client, because of job merging.
         */
	sd_bus_track *clients;
	char **deserialized_clients;

	JobResult result;

	bool installed: 1;
	bool in_run_queue: 1;
	bool matters_to_anchor: 1;
	bool override: 1;
	bool in_dbus_queue: 1;
	bool sent_dbus_new_signal: 1;
	bool ignore_order: 1;
	bool irreversible: 1;
	bool reloaded: 1;
};

Job *job_new(Unit *unit, JobType type);
Job *job_new_raw(Unit *unit);
void job_unlink(Job *job);
void job_free(Job *job);
Job *job_install(Job *j);
int job_install_deserialized(Job *j);
void job_uninstall(Job *j);
void job_dump(Job *j, FILE *f, const char *prefix);
int job_serialize(Job *j, FILE *f, FDSet *fds);
int job_deserialize(Job *j, FILE *f, FDSet *fds);
int job_coldplug(Job *j);

JobDependency *job_dependency_new(Job *subject, Job *object, bool matters,
	bool conflicts);
void job_dependency_free(JobDependency *l);

int job_merge(Job *j, Job *other);

JobType job_type_lookup_merge(JobType a, JobType b) _pure_;

_pure_ static inline bool
job_type_is_mergeable(JobType a, JobType b)
{
	return job_type_lookup_merge(a, b) >= 0;
}

_pure_ static inline bool
job_type_is_conflicting(JobType a, JobType b)
{
	return a != JOB_NOP && b != JOB_NOP && !job_type_is_mergeable(a, b);
}

_pure_ static inline bool
job_type_is_superset(JobType a, JobType b)
{
	/* Checks whether operation a is a "superset" of b in its actions */
	if (b == JOB_NOP)
		return true;
	if (a == JOB_NOP)
		return false;
	return a == job_type_lookup_merge(a, b);
}

bool job_type_is_redundant(JobType a, UnitActiveState b) _pure_;

/* Collapses a state-dependent job type into a simpler type by observing
 * the state of the unit which it is going to be applied to. */
JobType job_type_collapse(JobType t, Unit *u);

int job_type_merge_and_collapse(JobType *a, JobType b, Unit *u);

void job_add_to_run_queue(Job *j);
void job_add_to_dbus_queue(Job *j);

int job_start_timer(Job *j);

int job_run_and_invalidate(Job *j);
int job_finish_and_invalidate(Job *j, JobResult result, bool recursive,
	bool already);

char *job_dbus_path(Job *j);

void job_shutdown_magic(Job *j);

const char *job_type_to_string(JobType t) _const_;
JobType job_type_from_string(const char *s) _pure_;

const char *job_state_to_string(JobState t) _const_;
JobState job_state_from_string(const char *s) _pure_;

const char *job_mode_to_string(JobMode t) _const_;
JobMode job_mode_from_string(const char *s) _pure_;

const char *job_result_to_string(JobResult t) _const_;
JobResult job_result_from_string(const char *s) _pure_;

int job_get_timeout(Job *j, uint64_t *timeout) _pure_;
