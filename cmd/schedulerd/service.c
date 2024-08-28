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

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "alloc-util.h"
#include "async.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "dbus-service.h"
#include "def.h"
#include "env-util.h"
#include "exit-status.h"
#include "fileio.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "manager.h"
#include "path-util.h"
#include "service.h"
#include "special.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "utf8.h"
#include "util.h"

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
	[SERVICE_DEAD] = UNIT_INACTIVE,
	[SERVICE_START_PRE] = UNIT_ACTIVATING,
	[SERVICE_START] = UNIT_ACTIVATING,
	[SERVICE_START_POST] = UNIT_ACTIVATING,
	[SERVICE_RUNNING] = UNIT_ACTIVE,
	[SERVICE_EXITED] = UNIT_ACTIVE,
	[SERVICE_RELOAD] = UNIT_RELOADING,
	[SERVICE_STOP] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGABRT] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
	[SERVICE_STOP_POST] = UNIT_DEACTIVATING,
	[SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
	[SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
	[SERVICE_FAILED] = UNIT_FAILED,
	[SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

/* For Type=idle we never want to delay any other jobs, hence we
 * consider idle jobs active as soon as we start working on them */
static const UnitActiveState state_translation_table_idle[_SERVICE_STATE_MAX] = {
	[SERVICE_DEAD] = UNIT_INACTIVE,
	[SERVICE_START_PRE] = UNIT_ACTIVE,
	[SERVICE_START] = UNIT_ACTIVE,
	[SERVICE_START_POST] = UNIT_ACTIVE,
	[SERVICE_RUNNING] = UNIT_ACTIVE,
	[SERVICE_EXITED] = UNIT_ACTIVE,
	[SERVICE_RELOAD] = UNIT_RELOADING,
	[SERVICE_STOP] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGABRT] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
	[SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
	[SERVICE_STOP_POST] = UNIT_DEACTIVATING,
	[SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
	[SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
	[SERVICE_FAILED] = UNIT_FAILED,
	[SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

static int service_dispatch_io(sd_event_source *source, int fd, uint32_t events,
	void *userdata);
static int service_dispatch_timer(sd_event_source *source, usec_t usec,
	void *userdata);
static int service_dispatch_watchdog(sd_event_source *source, usec_t usec,
	void *userdata);

static void service_enter_signal(Service *s, ServiceState state,
	ServiceResult f);
static void service_enter_reload_by_notify(Service *s);

static void
service_init(Unit *u)
{
	Service *s = SERVICE(u);

	assert(u);
	assert(u->load_state == UNIT_STUB);

	s->timeout_start_usec = u->manager->default_timeout_start_usec;
	s->timeout_stop_usec = u->manager->default_timeout_stop_usec;
	s->restart_usec = u->manager->default_restart_usec;
	s->type = _SERVICE_TYPE_INVALID;
	s->socket_fd = -1;
	s->guess_main_pid = true;

	RATELIMIT_INIT(s->start_limit, u->manager->default_start_limit_interval,
		u->manager->default_start_limit_burst);

	s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
}

static void
service_unwatch_control_pid(Service *s)
{
	assert(s);

	if (s->control_pid <= 0)
		return;

	unit_unwatch_pid(UNIT(s), s->control_pid);
	s->control_pid = 0;
}

static void
service_unwatch_main_pid(Service *s)
{
	assert(s);

	if (s->main_pid <= 0)
		return;

	unit_unwatch_pid(UNIT(s), s->main_pid);
	s->main_pid = 0;
}

static void
service_unwatch_pid_file(Service *s)
{
	if (!s->pid_file_pathspec)
		return;

	log_unit_debug(UNIT(s)->id, "Stopping watch for %s's PID file %s",
		UNIT(s)->id, s->pid_file_pathspec->path);
	path_spec_unwatch(s->pid_file_pathspec);
	path_spec_done(s->pid_file_pathspec);
	free(s->pid_file_pathspec);
	s->pid_file_pathspec = NULL;
}

static int
service_set_main_pid(Service *s, pid_t pid)
{
	assert(s);

	if (pid <= 1)
		return -EINVAL;

	if (pid == getpid())
		return -EINVAL;

	if (s->main_pid == pid && s->main_pid_known)
		return 0;

	if (s->main_pid != pid) {
		service_unwatch_main_pid(s);
		exec_status_start(&s->main_exec_status, pid);
	}

	s->main_pid = pid;
	s->main_pid_known = true;
	s->main_pid_alien = pid_is_my_child(pid) == 0;

	if (s->main_pid_alien)
		log_unit_warning(UNIT(s)->id,
			"%s: Supervising process " PID_FMT
			" which is not our child. We'll most likely not notice when it exits.",
			UNIT(s)->id, pid);

	return 0;
}

static void
service_close_socket_fd(Service *s)
{
	assert(s);

	s->socket_fd = asynchronous_close(s->socket_fd);
}

static void
service_connection_unref(Service *s)
{
	assert(s);

	if (!UNIT_ISSET(s->accept_socket))
		return;

	socket_connection_unref(SOCKET(UNIT_DEREF(s->accept_socket)));
	unit_ref_unset(&s->accept_socket);
}

static void
service_stop_watchdog(Service *s)
{
	assert(s);

	s->watchdog_event_source =
		sd_event_source_unref(s->watchdog_event_source);
	s->watchdog_timestamp = DUAL_TIMESTAMP_NULL;
}

static void
service_start_watchdog(Service *s)
{
	int r;

	assert(s);

	if (s->watchdog_usec <= 0)
		return;

	if (s->watchdog_event_source) {
		r = sd_event_source_set_time(s->watchdog_event_source,
			s->watchdog_timestamp.monotonic + s->watchdog_usec);
		if (r < 0) {
			log_unit_warning_errno(UNIT(s)->id, r,
				"%s failed to reset watchdog timer: %m",
				UNIT(s)->id);
			return;
		}

		r = sd_event_source_set_enabled(s->watchdog_event_source,
			SD_EVENT_ONESHOT);
	} else {
		r = sd_event_add_time(UNIT(s)->manager->event,
			&s->watchdog_event_source, CLOCK_MONOTONIC,
			s->watchdog_timestamp.monotonic + s->watchdog_usec, 0,
			service_dispatch_watchdog, s);
		if (r < 0) {
			log_unit_warning_errno(UNIT(s)->id, r,
				"%s failed to add watchdog timer: %m",
				UNIT(s)->id);
			return;
		}

		/* Let's process everything else which might be a sign
                 * of living before we consider a service died. */
		r = sd_event_source_set_priority(s->watchdog_event_source,
			SD_EVENT_PRIORITY_IDLE);
	}

	if (r < 0)
		log_unit_warning_errno(UNIT(s)->id, r,
			"%s failed to install watchdog timer: %m", UNIT(s)->id);
}

static void
service_reset_watchdog(Service *s)
{
	assert(s);

	dual_timestamp_get(&s->watchdog_timestamp);
	service_start_watchdog(s);
}

static void
service_fd_store_unlink(ServiceFDStore *fs)
{
	if (!fs)
		return;

	if (fs->service) {
		assert(fs->service->n_fd_store > 0);
		IWLIST_REMOVE(fd_store, fs->service->fd_store, fs);
		fs->service->n_fd_store--;
	}

	if (fs->event_source) {
		sd_event_source_set_enabled(fs->event_source, SD_EVENT_OFF);
		sd_event_source_unref(fs->event_source);
	}

	safe_close(fs->fd);
	free(fs);
}

static void
service_release_fd_store(Service *s)
{
	assert(s);

	if (s->n_keep_fd_store > 0)
		return;

	log_unit_debug(UNIT(s)->id, "Releasing all stored fds");
	while (s->fd_store)
		service_fd_store_unlink(s->fd_store);

	assert(s->n_fd_store == 0);
}

static void
service_release_resources(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	if (!s->fd_store)
		return;

	log_unit_debug(u->id, "Releasing resources.");

	service_release_fd_store(s);
}

static void
service_done(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	free(s->pid_file);
	s->pid_file = NULL;

	free(s->status_text);
	s->status_text = NULL;

	free(s->reboot_arg);
	s->reboot_arg = NULL;

	s->exec_runtime = exec_runtime_unref(s->exec_runtime);
	exec_command_free_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
	s->control_command = NULL;
	s->main_command = NULL;

	exit_status_set_free(&s->restart_prevent_status);
	exit_status_set_free(&s->restart_force_status);
	exit_status_set_free(&s->success_status);

	/* This will leak a process, but at least no memory or any of
         * our resources */
	service_unwatch_main_pid(s);
	service_unwatch_control_pid(s);
	service_unwatch_pid_file(s);

	if (s->bus_name) {
		unit_unwatch_bus_name(u, s->bus_name);
		free(s->bus_name);
		s->bus_name = NULL;
	}

	service_close_socket_fd(s);
	service_connection_unref(s);

	unit_ref_unset(&s->accept_socket);

	service_stop_watchdog(s);

	s->timer_event_source = sd_event_source_unref(s->timer_event_source);

	service_release_resources(u);
}

static int
on_fd_store_io(sd_event_source *e, int fd, uint32_t revents, void *userdata)
{
	ServiceFDStore *fs = userdata;

	assert(e);
	assert(fs);

	/* If we get either EPOLLHUP or EPOLLERR, it's time to remove this entry from the fd store */
	service_fd_store_unlink(fs);
	return 0;
}

static int
service_add_fd_store(Service *s, int fd)
{
	ServiceFDStore *fs;
	int r;

	assert(s);
	assert(fd >= 0);

	if (s->n_fd_store >= s->n_fd_store_max)
		return 0;

	IWLIST_FOREACH (fd_store, fs, s->fd_store) {
		r = same_fd(fs->fd, fd);
		if (r < 0)
			return r;
		if (r > 0) {
			/* Already included */
			safe_close(fd);
			return 1;
		}
	}

	fs = new0(ServiceFDStore, 1);
	if (!fs)
		return -ENOMEM;

	fs->fd = fd;
	fs->service = s;

	r = sd_event_add_io(UNIT(s)->manager->event, &fs->event_source, fd, 0,
		on_fd_store_io, fs);
	if (r < 0) {
		free(fs);
		return r;
	}

	IWLIST_PREPEND(fd_store, s->fd_store, fs);
	s->n_fd_store++;

	return 1;
}

static int
service_add_fd_store_set(Service *s, FDSet *fds)
{
	int r;

	assert(s);

	if (fdset_size(fds) <= 0)
		return 0;

	while (s->n_fd_store < s->n_fd_store_max) {
		_cleanup_close_ int fd = -1;

		fd = fdset_steal_first(fds);
		if (fd < 0)
			break;

		r = service_add_fd_store(s, fd);
		if (r < 0)
			return log_unit_error_errno(UNIT(s)->id, r,
				"%s: Couldn't add fd to fd store: %m",
				UNIT(s)->id);

		if (r > 0) {
			log_unit_debug(UNIT(s)->id, "%s: added fd to fd store.",
				UNIT(s)->id);
			fd = -1;
		}
	}

	if (fdset_size(fds) > 0)
		log_unit_warning(UNIT(s)->id,
			"%s: tried to store more fds than FDStoreMax=%u allows, closing remaining.",
			UNIT(s)->id, s->n_fd_store_max);

	return 0;
}

static int
service_arm_timer(Service *s, usec_t usec)
{
	int r;

	assert(s);

	if (s->timer_event_source) {
		r = sd_event_source_set_time(s->timer_event_source,
			now(CLOCK_MONOTONIC) + usec);
		if (r < 0)
			return r;

		return sd_event_source_set_enabled(s->timer_event_source,
			SD_EVENT_ONESHOT);
	}

	return sd_event_add_time(UNIT(s)->manager->event,
		&s->timer_event_source, CLOCK_MONOTONIC,
		now(CLOCK_MONOTONIC) + usec, 0, service_dispatch_timer, s);
}

static int
service_verify(Service *s)
{
	assert(s);

	if (UNIT(s)->load_state != UNIT_LOADED)
		return 0;

	if (!s->exec_command[SERVICE_EXEC_START] &&
		!s->exec_command[SERVICE_EXEC_STOP]) {
		log_unit_error(UNIT(s)->id,
			"%s lacks both ExecStart= and ExecStop= setting. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->type != SERVICE_ONESHOT &&
		!s->exec_command[SERVICE_EXEC_START]) {
		log_unit_error(UNIT(s)->id,
			"%s has no ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (!s->remain_after_exit && !s->exec_command[SERVICE_EXEC_START]) {
		log_unit_error(UNIT(s)->id,
			"%s has no ExecStart= setting, which is only allowed for RemainAfterExit=yes services. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->type != SERVICE_ONESHOT &&
		s->exec_command[SERVICE_EXEC_START]->command_next) {
		log_unit_error(UNIT(s)->id,
			"%s has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->type == SERVICE_ONESHOT && s->restart != SERVICE_RESTART_NO) {
		log_unit_error(UNIT(s)->id,
			"%s has Restart= setting other than no, which isn't allowed for Type=oneshot services. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->type == SERVICE_ONESHOT &&
		!exit_status_set_is_empty(&s->restart_force_status)) {
		log_unit_error(UNIT(s)->id,
			"%s has RestartForceStatus= set, which isn't allowed for Type=oneshot services. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->type == SERVICE_DBUS && !s->bus_name) {
		log_unit_error(UNIT(s)->id,
			"%s is of type D-Bus but no D-Bus service name has been specified. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	if (s->bus_name && s->type != SERVICE_DBUS)
		log_unit_warning(UNIT(s)->id,
			"%s has a D-Bus service name specified, but is not of type dbus. Ignoring.",
			UNIT(s)->id);

	if (s->exec_context.pam_name &&
		!(s->kill_context.kill_mode == KILL_CONTROL_GROUP ||
			s->kill_context.kill_mode == KILL_MIXED)) {
		log_unit_error(UNIT(s)->id,
			"%s has PAM enabled. Kill mode must be set to 'control-group' or 'mixed'. Refusing.",
			UNIT(s)->id);
		return -EINVAL;
	}

	return 0;
}

static int
service_add_default_dependencies(Service *s)
{
	int r;

	assert(s);

	/* Add a number of automatic dependencies useful for the
         * majority of services. */

	/* First, pull in base system */
	r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER,
		UNIT_REQUIRES, SPECIAL_BASIC_TARGET, NULL, true);
	if (r < 0)
		return r;

	/* Second, activate normal shutdown */
	return unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE,
		UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static void
service_fix_output(Service *s)
{
	assert(s);

	/* If nothing has been explicitly configured, patch default
         * output in. If input is socket/tty we avoid this however,
         * since in that case we want output to default to the same
         * place as we read input from. */

	if (s->exec_context.std_error == EXEC_OUTPUT_INHERIT &&
		s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
		s->exec_context.std_input == EXEC_INPUT_NULL)
		s->exec_context.std_error = UNIT(s)->manager->default_std_error;

	if (s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
		s->exec_context.std_input == EXEC_INPUT_NULL)
		s->exec_context.std_output =
			UNIT(s)->manager->default_std_output;
}

static int
service_add_extras(Service *s)
{
	int r;

	assert(s);

	if (s->type == _SERVICE_TYPE_INVALID) {
		/* Figure out a type automatically */
		if (s->bus_name)
			s->type = SERVICE_DBUS;
		else if (s->exec_command[SERVICE_EXEC_START])
			s->type = SERVICE_SIMPLE;
		else
			s->type = SERVICE_ONESHOT;
	}

	/* Oneshot services have disabled start timeout by default */
	if (s->type == SERVICE_ONESHOT && !s->start_timeout_defined)
		s->timeout_start_usec = 0;

	service_fix_output(s);

	r = unit_patch_contexts(UNIT(s));
	if (r < 0)
		return r;

	r = unit_add_exec_dependencies(UNIT(s), &s->exec_context);
	if (r < 0)
		return r;

	r = unit_add_default_slice(UNIT(s), &s->cgroup_context);
	if (r < 0)
		return r;

	if (s->type == SERVICE_NOTIFY && s->notify_access == NOTIFY_NONE)
		s->notify_access = NOTIFY_MAIN;

	if (s->watchdog_usec > 0 && s->notify_access == NOTIFY_NONE)
		s->notify_access = NOTIFY_MAIN;

	if (s->bus_name) {
		r = unit_watch_bus_name(UNIT(s), s->bus_name);
		if (r < 0)
			return r;
	}

	if (UNIT(s)->default_dependencies) {
		r = service_add_default_dependencies(s);
		if (r < 0)
			return r;
	}

	return 0;
}

static int
service_load(Unit *u)
{
	Service *s = SERVICE(u);
	int r;

	assert(s);

	/* Load a .service file */
	r = unit_load_fragment(u);
	if (r < 0)
		return r;

	/* Still nothing found? Then let's give up */
	if (u->load_state == UNIT_STUB)
		return -ENOENT;

	/* This is a new unit? Then let's add in some extras */
	if (u->load_state == UNIT_LOADED) {
		/* We were able to load something, then let's add in
                 * the dropin directories. */
		r = unit_load_dropin(u);
		if (r < 0)
			return r;

		/* This is a new unit? Then let's add in some
                 * extras */
		r = service_add_extras(s);
		if (r < 0)
			return r;
	}

	return service_verify(s);
}

static void
service_dump(Unit *u, FILE *f, const char *prefix)
{
	ServiceExecCommand c;
	Service *s = SERVICE(u);
	const char *prefix2;

	assert(s);

	prefix = strempty(prefix);
	prefix2 = strjoina(prefix, "\t");

	fprintf(f,
		"%sService State: %s\n"
		"%sResult: %s\n"
		"%sReload Result: %s\n"
		"%sPermissionsStartOnly: %s\n"
		"%sRootDirectoryStartOnly: %s\n"
		"%sRemainAfterExit: %s\n"
		"%sGuessMainPID: %s\n"
		"%sType: %s\n"
		"%sRestart: %s\n"
		"%sNotifyAccess: %s\n"
		"%sNotifyState: %s\n",
		prefix, service_state_to_string(s->state), prefix,
		service_result_to_string(s->result), prefix,
		service_result_to_string(s->reload_result), prefix,
		yes_no(s->permissions_start_only), prefix,
		yes_no(s->root_directory_start_only), prefix,
		yes_no(s->remain_after_exit), prefix, yes_no(s->guess_main_pid),
		prefix, service_type_to_string(s->type), prefix,
		service_restart_to_string(s->restart), prefix,
		notify_access_to_string(s->notify_access), prefix,
		notify_state_to_string(s->notify_state));

	if (s->control_pid > 0)
		fprintf(f, "%sControl PID: " PID_FMT "\n", prefix,
			s->control_pid);

	if (s->main_pid > 0)
		fprintf(f,
			"%sMain PID: " PID_FMT "\n"
			"%sMain PID Known: %s\n"
			"%sMain PID Alien: %s\n",
			prefix, s->main_pid, prefix, yes_no(s->main_pid_known),
			prefix, yes_no(s->main_pid_alien));

	if (s->pid_file)
		fprintf(f, "%sPIDFile: %s\n", prefix, s->pid_file);

	if (s->bus_name)
		fprintf(f,
			"%sBusName: %s\n"
			"%sBus Name Good: %s\n",
			prefix, s->bus_name, prefix, yes_no(s->bus_name_good));

	kill_context_dump(&s->kill_context, f, prefix);
	exec_context_dump(&s->exec_context, f, prefix);

	for (c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++) {
		if (!s->exec_command[c])
			continue;

		fprintf(f, "%s-> %s:\n", prefix,
			service_exec_command_to_string(c));

		exec_command_dump_list(s->exec_command[c], f, prefix2);
	}

	if (s->status_text)
		fprintf(f, "%sStatus Text: %s\n", prefix, s->status_text);

	if (s->n_fd_store_max > 0) {
		fprintf(f,
			"%sFile Descriptor Store Max: %u\n"
			"%sFile Descriptor Store Current: %u\n",
			prefix, s->n_fd_store_max, prefix, s->n_fd_store);
	}
}

static int
service_is_suitable_main_pid(Service *s, pid_t pid, int prio)
{
	Unit *owner;

	assert(s);
	assert(pid > 0);

	/* Checks whether the specified PID is suitable as main PID for this service. returns negative if not, 0 if the
         * PID is questionnable but should be accepted if the source of configuration is trusted. > 0 if the PID is
         * good */

	if (pid == getpid() || pid == 1) {
		log_unit_full(UNIT(s)->id, prio,
			"New main PID " PID_FMT " is the manager, refusing.",
			pid);
		return -EPERM;
	}

	if (pid == s->control_pid) {
		log_unit_full(UNIT(s)->id, prio,
			"New main PID " PID_FMT
			" is the control process, refusing.",
			pid);
		return -EPERM;
	}

	if (!pid_is_alive(pid)) {
		log_unit_full(UNIT(s)->id, prio,
			"New main PID " PID_FMT
			" does not exist or is a zombie.",
			pid);
		return -ESRCH;
	}

	owner = manager_get_unit_by_pid(UNIT(s)->manager, pid);
	if (owner == UNIT(s)) {
		log_unit_debug(UNIT(s)->id,
			"New main PID " PID_FMT
			" belongs to service, we are happy.",
			pid);
		return 1; /* Yay, it's definitely a good PID */
	}

	return 0; /* Hmm it's a suspicious PID, let's accept it if configuration source is trusted */
}

static int
service_load_pid_file(Service *s, bool may_warn)
{
	char procfs[sizeof("/proc/self/fd/") - 1 + DECIMAL_STR_MAX(int)];
	bool questionable_pid_file = false;
	_cleanup_free_ char *k = NULL;
	_cleanup_close_ int fd = -1;
	int r, prio;
	pid_t pid;

	assert(s);

	if (!s->pid_file)
		return -ENOENT;

	prio = may_warn ? LOG_INFO : LOG_DEBUG;

	fd = chase_symlinks(s->pid_file, NULL, CHASE_OPEN | CHASE_SAFE, NULL);
	if (fd == -EPERM) {
		log_unit_full(UNIT(s)->id, LOG_DEBUG,
			"Permission denied while opening PID file or potentially unsafe symlink chain, will now retry with relaxed checks: %s",
			s->pid_file);

		questionable_pid_file = true;

		fd = chase_symlinks(s->pid_file, NULL, CHASE_OPEN, NULL);
	}
	if (fd < 0)
		return log_unit_full_errno(UNIT(s)->id, prio, fd,
			"Can't open PID file %s (yet?) after %s: %m",
			s->pid_file, service_state_to_string(s->state));

	/* Let's read the PID file now that we chased it down. But we need to convert the O_PATH fd chase_symlinks() returned us into a proper fd first. */
	xsprintf(procfs, "/proc/self/fd/%i", fd);
	r = read_one_line_file(procfs, &k);
	if (r < 0)
		return log_unit_error_errno(UNIT(s)->id, r,
			"Can't convert PID files %s O_PATH file descriptor to proper file descriptor: %m",
			s->pid_file);

	r = parse_pid(k, &pid);
	if (r < 0)
		return log_unit_full_errno(UNIT(s)->id, prio, r,
			"Failed to parse PID from file %s: %m", s->pid_file);

	if (s->main_pid_known && pid == s->main_pid)
		return 0;

	r = service_is_suitable_main_pid(s, pid, prio);
	if (r < 0)
		return r;
	if (r == 0) {
		struct stat st;

		if (questionable_pid_file) {
			log_unit_error(UNIT(s)->id,
				"Refusing to accept PID outside of service control group, acquired through unsafe symlink chain: %s",
				s->pid_file);
			return -EPERM;
		}

		/* Hmm, it's not clear if the new main PID is safe. Let's allow this if the PID file is owned by root */

		if (fstat(fd, &st) < 0)
			return log_unit_error_errno(UNIT(s)->id, errno,
				"Failed to fstat() PID file O_PATH fd: %m");

		if (st.st_uid != 0) {
			log_unit_error(UNIT(s)->id,
				"New main PID " PID_FMT
				" does not belong to service, and PID file is not owned by root. Refusing.",
				pid);
			return -EPERM;
		}

		log_unit_debug(UNIT(s)->id,
			"New main PID " PID_FMT
			" does not belong to service, but we'll accept it since PID file is owned by root.",
			pid);
	}

	if (s->main_pid_known) {
		log_unit_debug(UNIT(s)->id,
			"Main PID changing: " PID_FMT " -> " PID_FMT,
			s->main_pid, pid);

		service_unwatch_main_pid(s);
		s->main_pid_known = false;
	} else
		log_unit_debug(UNIT(s)->id, "Main PID loaded: " PID_FMT, pid);

	r = service_set_main_pid(s, pid);
	if (r < 0)
		return r;

	r = unit_watch_pid(UNIT(s), pid, false);
	if (r < 0) {
		/* FIXME: we need to do something here */
		log_unit_warning(UNIT(s)->id,
			"Failed to watch PID " PID_FMT " from service %s", pid,
			UNIT(s)->id);
		return r;
	}

	return 1;
}

static int
service_search_main_pid(Service *s)
{
	pid_t pid;
	int r;

	assert(s);

	/* If we know it anyway, don't ever fallback to unreliable
         * heuristics */
	if (s->main_pid_known)
		return 0;

	if (!s->guess_main_pid)
		return 0;

	assert(s->main_pid <= 0);

	pid = unit_search_main_pid(UNIT(s));
	if (pid <= 0)
		return -ENOENT;

	log_unit_debug(UNIT(s)->id, "Main PID guessed: " PID_FMT, pid);
	r = service_set_main_pid(s, pid);
	if (r < 0)
		return r;

	r = unit_watch_pid(UNIT(s), pid, false);
	if (r < 0) {
		/* FIXME: we need to do something here */
		log_unit_warning(UNIT(s)->id,
			"Failed to watch PID " PID_FMT " from service %s", pid,
			UNIT(s)->id);
		return r;
	}

	return 0;
}

static void
service_set_state(Service *s, ServiceState state)
{
	ServiceState old_state;
	const UnitActiveState *table;

	assert(s);

	table = s->type == SERVICE_IDLE ? state_translation_table_idle :
						state_translation_table;

	old_state = s->state;
	s->state = state;

	service_unwatch_pid_file(s);

	if (!IN_SET(state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
		    SERVICE_RELOAD, SERVICE_STOP, SERVICE_STOP_SIGTERM,
		    SERVICE_STOP_SIGKILL, SERVICE_STOP_SIGABRT,
		    SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM,
		    SERVICE_FINAL_SIGKILL, SERVICE_AUTO_RESTART))
		s->timer_event_source =
			sd_event_source_unref(s->timer_event_source);

	if (!IN_SET(state, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING,
		    SERVICE_RELOAD, SERVICE_STOP, SERVICE_STOP_SIGTERM,
		    SERVICE_STOP_SIGKILL, SERVICE_STOP_SIGABRT,
		    SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM,
		    SERVICE_FINAL_SIGKILL)) {
		service_unwatch_main_pid(s);
		s->main_command = NULL;
	}

	if (!IN_SET(state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
		    SERVICE_RELOAD, SERVICE_STOP, SERVICE_STOP_SIGTERM,
		    SERVICE_STOP_SIGKILL, SERVICE_STOP_SIGABRT,
		    SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM,
		    SERVICE_FINAL_SIGKILL)) {
		service_unwatch_control_pid(s);
		s->control_command = NULL;
		s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
	}

	if (IN_SET(state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART))
		unit_unwatch_all_pids(UNIT(s));

	if (!IN_SET(state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
		    SERVICE_RUNNING, SERVICE_RELOAD, SERVICE_STOP,
		    SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL,
		    SERVICE_STOP_POST, SERVICE_STOP_SIGABRT,
		    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL) &&
		!(state == SERVICE_DEAD && UNIT(s)->job)) {
		service_close_socket_fd(s);
		service_connection_unref(s);
	}

	if (!IN_SET(state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
		service_stop_watchdog(s);

	/* For the inactive states unit_notify() will trim the cgroup,
         * but for exit we have to do that ourselves... */
	if (state == SERVICE_EXITED && UNIT(s)->manager->n_reloading <= 0)
		unit_destroy_cgroup_if_empty(UNIT(s));

	if (old_state != state)
		log_unit_debug(UNIT(s)->id, "%s changed %s -> %s", UNIT(s)->id,
			service_state_to_string(old_state),
			service_state_to_string(state));

	unit_notify(UNIT(s), table[old_state], table[state],
		s->reload_result == SERVICE_SUCCESS);
	s->reload_result = SERVICE_SUCCESS;
}

static int
service_coldplug(Unit *u, Hashmap *deferred_work)
{
	Service *s = SERVICE(u);
	int r;

	assert(s);
	assert(s->state == SERVICE_DEAD);

	if (s->deserialized_state != s->state) {
		if (IN_SET(s->deserialized_state, SERVICE_START_PRE,
			    SERVICE_START, SERVICE_START_POST, SERVICE_RELOAD,
			    SERVICE_STOP, SERVICE_STOP_SIGTERM,
			    SERVICE_STOP_SIGKILL, SERVICE_STOP_SIGABRT,
			    SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM,
			    SERVICE_FINAL_SIGKILL)) {
			usec_t k;

			k = IN_SET(s->deserialized_state, SERVICE_START_PRE,
				    SERVICE_START, SERVICE_START_POST,
				    SERVICE_RELOAD) ?
				      s->timeout_start_usec :
				      s->timeout_stop_usec;

			/* For the start/stop timeouts 0 means off */
			if (k > 0) {
				r = service_arm_timer(s, k);
				if (r < 0)
					return r;
			}
		}

		if (s->deserialized_state == SERVICE_AUTO_RESTART) {
			/* The restart timeouts 0 means immediately */
			r = service_arm_timer(s, s->restart_usec);
			if (r < 0)
				return r;
		}

		if (pid_is_unwaited(s->main_pid) &&
			((s->deserialized_state == SERVICE_START &&
				 IN_SET(s->type, SERVICE_FORKING, SERVICE_DBUS,
					 SERVICE_ONESHOT, SERVICE_NOTIFY)) ||
				IN_SET(s->deserialized_state, SERVICE_START,
					SERVICE_START_POST, SERVICE_RUNNING,
					SERVICE_RELOAD, SERVICE_STOP,
					SERVICE_STOP_SIGTERM,
					SERVICE_STOP_SIGKILL,
					SERVICE_STOP_SIGABRT, SERVICE_STOP_POST,
					SERVICE_FINAL_SIGTERM,
					SERVICE_FINAL_SIGKILL))) {
			r = unit_watch_pid(UNIT(s), s->main_pid, false);
			if (r < 0)
				return r;
		}

		if (pid_is_unwaited(s->control_pid) &&
			IN_SET(s->deserialized_state, SERVICE_START_PRE,
				SERVICE_START, SERVICE_START_POST,
				SERVICE_RELOAD, SERVICE_STOP,
				SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL,
				SERVICE_STOP_SIGABRT, SERVICE_STOP_POST,
				SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
			r = unit_watch_pid(UNIT(s), s->control_pid, false);
			if (r < 0)
				return r;
		}

		if (!IN_SET(s->deserialized_state, SERVICE_DEAD, SERVICE_FAILED,
			    SERVICE_AUTO_RESTART))
			unit_watch_all_pids(UNIT(s));

		if (IN_SET(s->deserialized_state, SERVICE_START_POST,
			    SERVICE_RUNNING, SERVICE_RELOAD))
			service_start_watchdog(s);

		service_set_state(s, s->deserialized_state);
	}

	return 0;
}

static int
service_collect_fds(Service *s, int **fds, unsigned *n_fds)
{
	_cleanup_free_ int *rfds = NULL;
	unsigned rn_fds = 0;
	Iterator i;
	int r;
	Unit *u;

	assert(s);
	assert(fds);
	assert(n_fds);

	if (s->socket_fd >= 0)
		return 0;

	SET_FOREACH (u, UNIT(s)->dependencies[UNIT_TRIGGERED_BY], i) {
		int *cfds;
		unsigned cn_fds;
		Socket *sock;

		if (u->type != UNIT_SOCKET)
			continue;

		sock = SOCKET(u);

		r = socket_collect_fds(sock, &cfds, &cn_fds);
		if (r < 0)
			return r;

		if (cn_fds <= 0) {
			free(cfds);
			continue;
		}

		if (!rfds) {
			rfds = cfds;
			rn_fds = cn_fds;
		} else {
			int *t;

			t = realloc(rfds, (rn_fds + cn_fds) * sizeof(int));
			if (!t) {
				free(cfds);
				return -ENOMEM;
			}

			memcpy(t + rn_fds, cfds, cn_fds * sizeof(int));
			rfds = t;
			rn_fds += cn_fds;

			free(cfds);
		}
	}

	if (s->n_fd_store > 0) {
		ServiceFDStore *fs;
		int *t;

		t = realloc(rfds, (rn_fds + s->n_fd_store) * sizeof(int));
		if (!t)
			return -ENOMEM;

		rfds = t;
		IWLIST_FOREACH (fd_store, fs, s->fd_store)
			rfds[rn_fds++] = fs->fd;
	}

	*fds = rfds;
	*n_fds = rn_fds;

	rfds = NULL;
	return 0;
}

static int
service_spawn(Service *s, ExecCommand *c, usec_t timeout, bool pass_fds,
	bool apply_permissions, bool apply_chroot, bool apply_tty_stdin,
	bool is_control, pid_t *_pid)
{
	pid_t pid;
	int r;
	int *fds = NULL;
	_cleanup_free_ int *fdsbuf = NULL;
	unsigned n_fds = 0, n_env = 0;
	_cleanup_free_ char *bus_endpoint_path = NULL;
	_cleanup_strv_free_ char **argv = NULL, **final_env = NULL,
				 **our_env = NULL;
	const char *path;
	ExecParameters exec_params = { .apply_permissions = apply_permissions,
		.apply_chroot = apply_chroot,
		.apply_tty_stdin = apply_tty_stdin,
		.selinux_context_net = s->socket_fd_selinux_context_net };

	assert(s);
	assert(c);
	assert(_pid);

	unit_realize_cgroup(UNIT(s));

	r = unit_setup_exec_runtime(UNIT(s));
	if (r < 0)
		goto fail;

	if (pass_fds || s->exec_context.std_input == EXEC_INPUT_SOCKET ||
		s->exec_context.std_output == EXEC_OUTPUT_SOCKET ||
		s->exec_context.std_error == EXEC_OUTPUT_SOCKET) {
		if (s->socket_fd >= 0) {
			fds = &s->socket_fd;
			n_fds = 1;
		} else {
			r = service_collect_fds(s, &fdsbuf, &n_fds);
			if (r < 0)
				goto fail;

			fds = fdsbuf;
		}
	}

	if (timeout > 0) {
		r = service_arm_timer(s, timeout);
		if (r < 0)
			goto fail;
	} else
		s->timer_event_source =
			sd_event_source_unref(s->timer_event_source);

	r = unit_full_printf_strv(UNIT(s), c->argv, &argv);
	if (r < 0)
		goto fail;

	our_env = new0(char *, 6);
	if (!our_env) {
		r = -ENOMEM;
		goto fail;
	}

	if (is_control ? s->notify_access == NOTIFY_ALL :
			       s->notify_access != NOTIFY_NONE)
		if (asprintf(our_env + n_env++, "NOTIFY_SOCKET=%s",
			    UNIT(s)->manager->notify_socket) < 0) {
			r = -ENOMEM;
			goto fail;
		}

	if (s->main_pid > 0)
		if (asprintf(our_env + n_env++, "MAINPID=" PID_FMT,
			    s->main_pid) < 0) {
			r = -ENOMEM;
			goto fail;
		}

	if (UNIT(s)->manager->running_as != SYSTEMD_SYSTEM)
		if (asprintf(our_env + n_env++, "MANAGERPID=" PID_FMT,
			    getpid()) < 0) {
			r = -ENOMEM;
			goto fail;
		}

	if (UNIT_DEREF(s->accept_socket)) {
		union sockaddr_union sa;
		socklen_t salen = sizeof(sa);

		r = getpeername(s->socket_fd, &sa.sa, &salen);
		if (r < 0) {
			r = -errno;
			goto fail;
		}

		if (IN_SET(sa.sa.sa_family, AF_INET, AF_INET6)) {
			_cleanup_free_ char *addr = NULL;
			char *t;
			int port;

			r = sockaddr_pretty(&sa.sa, salen, true, false, &addr);
			if (r < 0)
				goto fail;

			t = strappend("REMOTE_ADDR=", addr);
			if (!t) {
				r = -ENOMEM;
				goto fail;
			}
			our_env[n_env++] = t;

			port = sockaddr_port(&sa.sa);
			if (port < 0) {
				r = port;
				goto fail;
			}

			if (asprintf(&t, "REMOTE_PORT=%u", port) < 0) {
				r = -ENOMEM;
				goto fail;
			}
			our_env[n_env++] = t;
		}
	}

	final_env =
		strv_env_merge(2, UNIT(s)->manager->environment, our_env, NULL);
	if (!final_env) {
		r = -ENOMEM;
		goto fail;
	}

	if (is_control && UNIT(s)->cgroup_path) {
		path = strjoina(UNIT(s)->cgroup_path, "/control");
		cg_create(SYSTEMD_CGROUP_CONTROLLER, path);
	} else
		path = UNIT(s)->cgroup_path;

	exec_params.argv = argv;
	exec_params.fds = fds;
	exec_params.n_fds = n_fds;
	exec_params.environment = final_env;
	exec_params.confirm_spawn = UNIT(s)->manager->confirm_spawn;
	exec_params.cgroup_supported = UNIT(s)->manager->cgroup_supported;
	exec_params.cgroup_path = path;
	exec_params.cgroup_delegate = s->cgroup_context.delegate;
	exec_params.runtime_prefix =
		manager_get_runtime_prefix(UNIT(s)->manager);
	exec_params.unit_id = UNIT(s)->id;
	exec_params.watchdog_usec = s->watchdog_usec;
	exec_params.bus_endpoint_path = bus_endpoint_path;
	if (s->type == SERVICE_IDLE)
		exec_params.idle_pipe = UNIT(s)->manager->idle_pipe;

	r = exec_spawn(c, &s->exec_context, &exec_params, s->exec_runtime,
		&pid);
	if (r < 0)
		goto fail;

	r = unit_watch_pid(UNIT(s), pid, true);
	if (r < 0)
		/* FIXME: we need to do something here */
		goto fail;

	*_pid = pid;

	return 0;

fail:
	if (timeout)
		s->timer_event_source =
			sd_event_source_unref(s->timer_event_source);

	return r;
}

static int
main_pid_good(Service *s)
{
	assert(s);

	/* Returns 0 if the pid is dead, 1 if it is good, -1 if we
         * don't know */

	/* If we know the pid file, then lets just check if it is
         * still valid */
	if (s->main_pid_known) {
		/* If it's an alien child let's check if it is still
                 * alive ... */
		if (s->main_pid_alien && s->main_pid > 0)
			return pid_is_alive(s->main_pid);

		/* .. otherwise assume we'll get a SIGCHLD for it,
                 * which we really should wait for to collect exit
                 * status and code */
		return s->main_pid > 0;
	}

	/* We don't know the pid */
	return -EAGAIN;
}

_pure_ static int
control_pid_good(Service *s)
{
	assert(s);

	return s->control_pid > 0;
}

static int
cgroup_good(Service *s)
{
	int r;

	assert(s);

	if (!UNIT(s)->cgroup_path)
		return 0;

	r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER,
		UNIT(s)->cgroup_path, true);
	if (r < 0)
		return r;

	return !r;
}

static void
service_enter_dead(Service *s, ServiceResult f, bool allow_restart)
{
	int r;

	assert(s);

	/* If there's a stop job queued before we enter the DEAD state, we shouldn't act on Restart=, in order to not
         * undo what has already been enqueued. */
	if (unit_stop_pending(UNIT(s)))
		allow_restart = false;

	if (f != SERVICE_SUCCESS)
		s->result = f;

	/* Make sure service_release_resources() doesn't destroy our FD store, while we are changing through
         * SERVICE_FAILED/SERVICE_DEAD before entering into SERVICE_AUTO_RESTART. */
	s->n_keep_fd_store++;

	service_set_state(s,
		s->result != SERVICE_SUCCESS ? SERVICE_FAILED : SERVICE_DEAD);

	if (s->result != SERVICE_SUCCESS) {
		log_unit_warning(UNIT(s)->id, "%s failed.", UNIT(s)->id);
		emergency_action(UNIT(s)->manager, s->emergency_action,
			s->reboot_arg, "service failed");
	}

	if (allow_restart && !s->forbid_restart &&
		(s->restart == SERVICE_RESTART_ALWAYS ||
			(s->restart == SERVICE_RESTART_ON_SUCCESS &&
				s->result == SERVICE_SUCCESS) ||
			(s->restart == SERVICE_RESTART_ON_FAILURE &&
				s->result != SERVICE_SUCCESS) ||
			(s->restart == SERVICE_RESTART_ON_ABNORMAL &&
				!IN_SET(s->result, SERVICE_SUCCESS,
					SERVICE_FAILURE_EXIT_CODE)) ||
			(s->restart == SERVICE_RESTART_ON_WATCHDOG &&
				s->result == SERVICE_FAILURE_WATCHDOG) ||
			(s->restart == SERVICE_RESTART_ON_ABORT &&
				IN_SET(s->result, SERVICE_FAILURE_SIGNAL,
					SERVICE_FAILURE_CORE_DUMP)) ||
			(s->main_exec_status.code == CLD_EXITED &&
				set_contains(s->restart_force_status.status,
					INT_TO_PTR(
						s->main_exec_status.status))) ||
			(IN_SET(s->main_exec_status.code, CLD_KILLED,
				 CLD_DUMPED) &&
				set_contains(s->restart_force_status.signal,
					INT_TO_PTR(
						s->main_exec_status.status)))) &&
		(s->main_exec_status.code != CLD_EXITED ||
			!set_contains(s->restart_prevent_status.status,
				INT_TO_PTR(s->main_exec_status.status))) &&
		(!IN_SET(s->main_exec_status.code, CLD_KILLED, CLD_DUMPED) ||
			!set_contains(s->restart_prevent_status.signal,
				INT_TO_PTR(s->main_exec_status.status)))) {
		r = service_arm_timer(s, s->restart_usec);
		if (r < 0) {
			s->n_keep_fd_store--;
			goto fail;
		}

		service_set_state(s, SERVICE_AUTO_RESTART);
	}

	/* The new state is in effect, let's decrease the fd store ref counter again. Let's also readd us to the GC
         * queue, so that the fd store is possibly gc'ed again */
	s->n_keep_fd_store--;
	unit_add_to_gc_queue(UNIT(s));

	s->forbid_restart = false;

	/* We want fresh tmpdirs in case service is started again immediately */
	exec_runtime_destroy(s->exec_runtime);
	s->exec_runtime = exec_runtime_unref(s->exec_runtime);

	/* Also, remove the runtime directory in */
	exec_context_destroy_runtime_directory(&s->exec_context,
		manager_get_runtime_prefix(UNIT(s)->manager));

	/* Try to delete the pid file. At this point it will be
         * out-of-date, and some software might be confused by it, so
         * let's remove it. */
	if (s->pid_file)
		unlink_noerrno(s->pid_file);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run install restart timer: %m", UNIT(s)->id);
	service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void
service_enter_stop_post(Service *s, ServiceResult f)
{
	int r;
	assert(s);

	if (f != SERVICE_SUCCESS)
		s->result = f;

	service_unwatch_control_pid(s);
	unit_watch_all_pids(UNIT(s));

	s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST];
	if (s->control_command) {
		s->control_command_id = SERVICE_EXEC_STOP_POST;

		r = service_spawn(s, s->control_command, s->timeout_stop_usec,
			false, !s->permissions_start_only,
			!s->root_directory_start_only, true, true,
			&s->control_pid);
		if (r < 0)
			goto fail;

		service_set_state(s, SERVICE_STOP_POST);
	} else
		service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_SUCCESS);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'stop-post' task: %m", UNIT(s)->id);
	service_enter_signal(s, SERVICE_FINAL_SIGTERM,
		SERVICE_FAILURE_RESOURCES);
}

static void
service_enter_signal(Service *s, ServiceState state, ServiceResult f)
{
	int r;

	assert(s);

	if (f != SERVICE_SUCCESS)
		s->result = f;

	unit_watch_all_pids(UNIT(s));

	r = unit_kill_context(UNIT(s), &s->kill_context,
		(state != SERVICE_STOP_SIGTERM &&
			state != SERVICE_FINAL_SIGTERM &&
			state != SERVICE_STOP_SIGABRT) ?
			      KILL_KILL :
			      (state == SERVICE_STOP_SIGABRT ? KILL_ABORT :
							       KILL_TERMINATE),
		s->main_pid, s->control_pid, s->main_pid_alien);

	if (r < 0)
		goto fail;

	if (r > 0) {
		if (s->timeout_stop_usec > 0) {
			r = service_arm_timer(s, s->timeout_stop_usec);
			if (r < 0)
				goto fail;
		}

		service_set_state(s, state);
	} else if (state == SERVICE_STOP_SIGTERM ||
		state == SERVICE_STOP_SIGABRT)
		service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_SUCCESS);
	else if (state == SERVICE_STOP_SIGKILL)
		service_enter_stop_post(s, SERVICE_SUCCESS);
	else if (state == SERVICE_FINAL_SIGTERM)
		service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
	else
		service_enter_dead(s, SERVICE_SUCCESS, true);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to kill processes: %m", UNIT(s)->id);

	if (state == SERVICE_STOP_SIGTERM || state == SERVICE_STOP_SIGKILL ||
		state == SERVICE_STOP_SIGABRT)
		service_enter_stop_post(s, SERVICE_FAILURE_RESOURCES);
	else
		service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void
service_enter_stop_by_notify(Service *s)
{
	assert(s);

	unit_watch_all_pids(UNIT(s));

	if (s->timeout_stop_usec > 0)
		service_arm_timer(s, s->timeout_stop_usec);

	/* The service told us it's stopping, so it's as if we SIGTERM'd it. */
	service_set_state(s, SERVICE_STOP_SIGTERM);
}

static void
service_enter_stop(Service *s, ServiceResult f)
{
	int r;

	assert(s);

	if (f != SERVICE_SUCCESS)
		s->result = f;

	service_unwatch_control_pid(s);
	unit_watch_all_pids(UNIT(s));

	s->control_command = s->exec_command[SERVICE_EXEC_STOP];
	if (s->control_command) {
		s->control_command_id = SERVICE_EXEC_STOP;

		r = service_spawn(s, s->control_command, s->timeout_stop_usec,
			false, !s->permissions_start_only,
			!s->root_directory_start_only, false, true,
			&s->control_pid);
		if (r < 0)
			goto fail;

		service_set_state(s, SERVICE_STOP);
	} else
		service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'stop' task: %m", UNIT(s)->id);
	service_enter_signal(s, SERVICE_STOP_SIGTERM,
		SERVICE_FAILURE_RESOURCES);
}

static void
service_enter_running(Service *s, ServiceResult f)
{
	int main_pid_ok, cgroup_ok;
	assert(s);

	if (f != SERVICE_SUCCESS)
		s->result = f;

	main_pid_ok = main_pid_good(s);
	cgroup_ok = cgroup_good(s);

	if ((main_pid_ok > 0 || (main_pid_ok < 0 && cgroup_ok != 0)) &&
		(s->bus_name_good || s->type != SERVICE_DBUS)) {
		/* If there are any queued up sd_notify()
                 * notifications, process them now */
		if (s->notify_state == NOTIFY_RELOADING)
			service_enter_reload_by_notify(s);
		else if (s->notify_state == NOTIFY_STOPPING)
			service_enter_stop_by_notify(s);
		else
			service_set_state(s, SERVICE_RUNNING);

	} else if (f != SERVICE_SUCCESS)
		service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
	else if (s->remain_after_exit)
		service_set_state(s, SERVICE_EXITED);
	else
		service_enter_stop(s, SERVICE_SUCCESS);
}

static void
service_enter_start_post(Service *s)
{
	int r;
	assert(s);

	service_unwatch_control_pid(s);
	service_reset_watchdog(s);

	s->control_command = s->exec_command[SERVICE_EXEC_START_POST];
	if (s->control_command) {
		s->control_command_id = SERVICE_EXEC_START_POST;

		r = service_spawn(s, s->control_command, s->timeout_start_usec,
			false, !s->permissions_start_only,
			!s->root_directory_start_only, false, true,
			&s->control_pid);
		if (r < 0)
			goto fail;

		service_set_state(s, SERVICE_START_POST);
	} else
		service_enter_running(s, SERVICE_SUCCESS);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'start-post' task: %m", UNIT(s)->id);
	service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void
service_kill_control_processes(Service *s)
{
	char *p;

	if (!UNIT(s)->cgroup_path)
		return;

	p = strjoina(UNIT(s)->cgroup_path, "/control");
	cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, p, SIGKILL, true, true,
		true, NULL);
}

static void
service_enter_start(Service *s)
{
	ExecCommand *c;
	pid_t pid;
	int r;

	assert(s);

	service_unwatch_control_pid(s);
	service_unwatch_main_pid(s);

	/* We want to ensure that nobody leaks processes from
         * START_PRE here, so let's go on a killing spree, People
         * should not spawn long running processes from START_PRE. */
	service_kill_control_processes(s);

	if (s->type == SERVICE_FORKING) {
		s->control_command_id = SERVICE_EXEC_START;
		c = s->control_command = s->exec_command[SERVICE_EXEC_START];

		s->main_command = NULL;
	} else {
		s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
		s->control_command = NULL;

		c = s->main_command = s->exec_command[SERVICE_EXEC_START];
	}

	if (!c) {
		if (s->type != SERVICE_ONESHOT) {
			/* There's no command line configured for the main command? Hmm, that is strange. This can only
                         * happen if the configuration changes at runtime. In this case, let's enter a failure
                         * state. */
			log_unit_error(UNIT(s)->id,
				"There's no 'start' task anymore we could start: %m");
			r = -ENXIO;
			goto fail;
		}

		service_enter_start_post(s);
		return;
	}

	r = service_spawn(s, c,
		IN_SET(s->type, SERVICE_FORKING, SERVICE_DBUS, SERVICE_NOTIFY,
			SERVICE_ONESHOT) ?
			      s->timeout_start_usec :
			      0,
		true, true, true, true, false, &pid);
	if (r < 0)
		goto fail;

	if (s->type == SERVICE_SIMPLE || s->type == SERVICE_IDLE) {
		/* For simple services we immediately start
                 * the START_POST binaries. */

		service_set_main_pid(s, pid);
		service_enter_start_post(s);

	} else if (s->type == SERVICE_FORKING) {
		/* For forking services we wait until the start
                 * process exited. */

		s->control_pid = pid;
		service_set_state(s, SERVICE_START);

	} else if (s->type == SERVICE_ONESHOT || s->type == SERVICE_DBUS ||
		s->type == SERVICE_NOTIFY) {
		/* For oneshot services we wait until the start
                 * process exited, too, but it is our main process. */

		/* For D-Bus services we know the main pid right away,
                 * but wait for the bus name to appear on the
                 * bus. Notify services are similar. */

		service_set_main_pid(s, pid);
		service_set_state(s, SERVICE_START);
	} else
		assert_not_reached();

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'start' task: %m", UNIT(s)->id);
	service_enter_signal(s, SERVICE_STOP_SIGTERM,
		SERVICE_FAILURE_RESOURCES);
}

static void
service_enter_start_pre(Service *s)
{
	int r;

	assert(s);

	service_unwatch_control_pid(s);

	s->control_command = s->exec_command[SERVICE_EXEC_START_PRE];
	if (s->control_command) {
		/* Before we start anything, let's clear up what might
                 * be left from previous runs. */
		service_kill_control_processes(s);

		s->control_command_id = SERVICE_EXEC_START_PRE;

		r = service_spawn(s, s->control_command, s->timeout_start_usec,
			false, !s->permissions_start_only,
			!s->root_directory_start_only, true, true,
			&s->control_pid);
		if (r < 0)
			goto fail;

		service_set_state(s, SERVICE_START_PRE);
	} else
		service_enter_start(s);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'start-pre' task: %m", UNIT(s)->id);
	service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void
service_enter_restart(Service *s)
{
	_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
	int r;

	assert(s);

	if (UNIT(s)->job && UNIT(s)->job->type == JOB_STOP) {
		/* Don't restart things if we are going down anyway */
		log_unit_info(UNIT(s)->id,
			"Stop job pending for unit, delaying automatic restart.");

		r = service_arm_timer(s, s->restart_usec);
		if (r < 0)
			goto fail;

		return;
	}

	/* Any units that are bound to this service must also be
         * restarted. We use JOB_RESTART (instead of the more obvious
         * JOB_START) here so that those dependency jobs will be added
         * as well. */
	r = manager_add_job(UNIT(s)->manager, JOB_RESTART, UNIT(s), JOB_FAIL,
		false, &error, NULL);
	if (r < 0)
		goto fail;

	/* Note that we stay in the SERVICE_AUTO_RESTART state here,
         * it will be canceled as part of the service_stop() call that
         * is executed as part of JOB_RESTART. */

	log_unit_debug(UNIT(s)->id, "%s scheduled restart job.", UNIT(s)->id);
	return;

fail:
	log_unit_warning(UNIT(s)->id, "%s failed to schedule restart job: %s",
		UNIT(s)->id, bus_error_message(&error, -r));
	service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void
service_enter_reload_by_notify(Service *s)
{
	assert(s);

	if (s->timeout_start_usec > 0)
		service_arm_timer(s, s->timeout_start_usec);

	service_set_state(s, SERVICE_RELOAD);
}

static void
service_enter_reload(Service *s)
{
	int r;

	assert(s);

	service_unwatch_control_pid(s);

	s->control_command = s->exec_command[SERVICE_EXEC_RELOAD];
	if (s->control_command) {
		s->control_command_id = SERVICE_EXEC_RELOAD;

		r = service_spawn(s, s->control_command, s->timeout_start_usec,
			false, !s->permissions_start_only,
			!s->root_directory_start_only, false, true,
			&s->control_pid);
		if (r < 0)
			goto fail;

		service_set_state(s, SERVICE_RELOAD);
	} else
		service_enter_running(s, SERVICE_SUCCESS);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run 'reload' task: %m", UNIT(s)->id);
	s->reload_result = SERVICE_FAILURE_RESOURCES;
	service_enter_running(s, SERVICE_SUCCESS);
}

static void
service_run_next_control(Service *s)
{
	int r;

	assert(s);
	assert(s->control_command);
	assert(s->control_command->command_next);

	assert(s->control_command_id != SERVICE_EXEC_START);

	s->control_command = s->control_command->command_next;
	service_unwatch_control_pid(s);

	r = service_spawn(s, s->control_command,
		IN_SET(s->state, SERVICE_START_PRE, SERVICE_START,
			SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD) ?
			      s->timeout_start_usec :
			      s->timeout_stop_usec,
		false, !s->permissions_start_only,
		!s->root_directory_start_only,
		s->control_command_id == SERVICE_EXEC_START_PRE ||
			s->control_command_id == SERVICE_EXEC_STOP_POST,
		true, &s->control_pid);
	if (r < 0)
		goto fail;

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run next control task: %m", UNIT(s)->id);

	if (IN_SET(s->state, SERVICE_START_PRE, SERVICE_STOP))
		service_enter_signal(s, SERVICE_STOP_SIGTERM,
			SERVICE_FAILURE_RESOURCES);
	else if (s->state == SERVICE_STOP_POST)
		service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
	else if (s->state == SERVICE_RELOAD) {
		s->reload_result = SERVICE_FAILURE_RESOURCES;
		service_enter_running(s, SERVICE_SUCCESS);
	} else
		service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void
service_run_next_main(Service *s)
{
	pid_t pid;
	int r;

	assert(s);
	assert(s->main_command);
	assert(s->main_command->command_next);
	assert(s->type == SERVICE_ONESHOT);

	s->main_command = s->main_command->command_next;
	service_unwatch_main_pid(s);

	r = service_spawn(s, s->main_command, s->timeout_start_usec, true, true,
		true, true, false, &pid);
	if (r < 0)
		goto fail;

	service_set_main_pid(s, pid);

	return;

fail:
	log_unit_warning_errno(UNIT(s)->id, r,
		"%s failed to run next main task: %m", UNIT(s)->id);
	service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static int
service_start_limit_test(Service *s)
{
	assert(s);

	if (ratelimit_test(&s->start_limit))
		return 0;

	log_unit_warning(UNIT(s)->id,
		"start request repeated too quickly for %s", UNIT(s)->id);

	return emergency_action(UNIT(s)->manager, s->start_limit_action,
		s->reboot_arg, "service failed");
}

static int
service_start(Unit *u)
{
	Service *s = SERVICE(u);
	int r;

	assert(s);

	/* We cannot fulfill this request right now, try again later
         * please! */
	if (s->state == SERVICE_STOP || s->state == SERVICE_STOP_SIGABRT ||
		s->state == SERVICE_STOP_SIGTERM ||
		s->state == SERVICE_STOP_SIGKILL ||
		s->state == SERVICE_STOP_POST ||
		s->state == SERVICE_FINAL_SIGTERM ||
		s->state == SERVICE_FINAL_SIGKILL)
		return -EAGAIN;

	/* Already on it! */
	if (s->state == SERVICE_START_PRE || s->state == SERVICE_START ||
		s->state == SERVICE_START_POST)
		return 0;

	/* A service that will be restarted must be stopped first to
         * trigger BindsTo and/or OnFailure dependencies. If a user
         * does not want to wait for the holdoff time to elapse, the
         * service should be manually restarted, not started. We
         * simply return EAGAIN here, so that any start jobs stay
         * queued, and assume that the auto restart timer will
         * eventually trigger the restart. */
	if (s->state == SERVICE_AUTO_RESTART)
		return -EAGAIN;

	assert(s->state == SERVICE_DEAD || s->state == SERVICE_FAILED);

	/* Make sure we don't enter a busy loop of some kind. */
	r = service_start_limit_test(s);
	if (r < 0) {
		service_enter_dead(s, SERVICE_FAILURE_START_LIMIT, false);
		return r;
	}

	s->result = SERVICE_SUCCESS;
	s->reload_result = SERVICE_SUCCESS;
	s->main_pid_known = false;
	s->main_pid_alien = false;
	s->forbid_restart = false;

	free(s->status_text);
	s->status_text = NULL;
	s->status_errno = 0;

	s->notify_state = NOTIFY_UNKNOWN;

	service_enter_start_pre(s);
	return 1;
}

static int
service_stop(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	/* Don't create restart jobs from here. */
	s->forbid_restart = true;

	/* Already on it */
	if (s->state == SERVICE_STOP || s->state == SERVICE_STOP_SIGABRT ||
		s->state == SERVICE_STOP_SIGTERM ||
		s->state == SERVICE_STOP_SIGKILL ||
		s->state == SERVICE_STOP_POST ||
		s->state == SERVICE_FINAL_SIGTERM ||
		s->state == SERVICE_FINAL_SIGKILL)
		return 0;

	/* A restart will be scheduled or is in progress. */
	if (s->state == SERVICE_AUTO_RESTART) {
		service_set_state(s, SERVICE_DEAD);
		return 0;
	}

	/* If there's already something running we go directly into
         * kill mode. */
	if (s->state == SERVICE_START_PRE || s->state == SERVICE_START ||
		s->state == SERVICE_START_POST || s->state == SERVICE_RELOAD) {
		service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
		return 0;
	}

	assert(s->state == SERVICE_RUNNING || s->state == SERVICE_EXITED);

	service_enter_stop(s, SERVICE_SUCCESS);
	return 1;
}

static int
service_reload(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	assert(s->state == SERVICE_RUNNING || s->state == SERVICE_EXITED);

	service_enter_reload(s);
	return 1;
}

_pure_ static bool
service_can_reload(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static unsigned
service_exec_command_index(Unit *u, ServiceExecCommand id, ExecCommand *current)
{
	Service *s = SERVICE(u);
	unsigned idx = 0;
	ExecCommand *first, *c;

	assert(s);

	first = s->exec_command[id];

	/* Figure out where we are in the list by walking back to the beginning */
	for (c = current; c != first; c = c->command_prev)
		idx++;

	return idx;
}

static int
service_serialize_exec_command(Unit *u, FILE *f, ExecCommand *command)
{
	Service *s = SERVICE(u);
	ServiceExecCommand id;
	unsigned idx;
	const char *type;
	char **arg;
	_cleanup_strv_free_ char **escaped_args = NULL;
	_cleanup_free_ char *args = NULL, *p = NULL;
	size_t length = 0;

	assert(s);
	assert(f);

	if (!command)
		return 0;

	if (command == s->control_command) {
		type = "control";
		id = s->control_command_id;
	} else {
		type = "main";
		id = SERVICE_EXEC_START;
	}

	idx = service_exec_command_index(u, id, command);

	STRV_FOREACH (arg, command->argv) {
		size_t n;
		_cleanup_free_ char *e = NULL;

		e = xescape(*arg, WHITESPACE);
		if (!e)
			return -ENOMEM;

		n = strlen(e);
		if (!GREEDY_REALLOC(args, length + 1 + n + 1))
			return -ENOMEM;

		if (length > 0)
			args[length++] = ' ';

		memcpy(args + length, e, n);
		length += n;
	}

	if (!GREEDY_REALLOC(args, length + 1))
		return -ENOMEM;
	args[length++] = 0;

	p = xescape(command->path, WHITESPACE);
	if (!p)
		return -ENOMEM;

	fprintf(f, "%s-command=%s %u %s %s\n", type,
		service_exec_command_to_string(id), idx, p, args);

	return 0;
}

static int
service_serialize(Unit *u, FILE *f, FDSet *fds)
{
	Service *s = SERVICE(u);
	ServiceFDStore *fs;

	assert(u);
	assert(f);
	assert(fds);

	unit_serialize_item(u, f, "state", service_state_to_string(s->state));
	unit_serialize_item(u, f, "result",
		service_result_to_string(s->result));
	unit_serialize_item(u, f, "reload-result",
		service_result_to_string(s->reload_result));

	if (s->control_pid > 0)
		unit_serialize_item_format(u, f, "control-pid", PID_FMT,
			s->control_pid);

	if (s->main_pid_known && s->main_pid > 0)
		unit_serialize_item_format(u, f, "main-pid", PID_FMT,
			s->main_pid);

	unit_serialize_item(u, f, "main-pid-known", yes_no(s->main_pid_known));
	unit_serialize_item(u, f, "bus-name-good", yes_no(s->bus_name_good));

	if (s->status_text)
		unit_serialize_item(u, f, "status-text", s->status_text);

	service_serialize_exec_command(u, f, s->control_command);
	service_serialize_exec_command(u, f, s->main_command);

	if (s->socket_fd >= 0) {
		int copy;

		copy = fdset_put_dup(fds, s->socket_fd);
		if (copy < 0)
			return copy;

		unit_serialize_item_format(u, f, "socket-fd", "%i", copy);
	}

	if (s->bus_endpoint_fd >= 0) {
		int copy;

		copy = fdset_put_dup(fds, s->bus_endpoint_fd);
		if (copy < 0)
			return copy;

		unit_serialize_item_format(u, f, "endpoint-fd", "%i", copy);
	}

	IWLIST_FOREACH (fd_store, fs, s->fd_store) {
		int copy;

		copy = fdset_put_dup(fds, fs->fd);
		if (copy < 0)
			return copy;

		unit_serialize_item_format(u, f, "fd-store-fd", "%i", copy);
	}

	if (s->main_exec_status.pid > 0) {
		unit_serialize_item_format(u, f, "main-exec-status-pid",
			PID_FMT, s->main_exec_status.pid);
		dual_timestamp_serialize(f, "main-exec-status-start",
			&s->main_exec_status.start_timestamp);
		dual_timestamp_serialize(f, "main-exec-status-exit",
			&s->main_exec_status.exit_timestamp);

		if (dual_timestamp_is_set(
			    &s->main_exec_status.exit_timestamp)) {
			unit_serialize_item_format(u, f,
				"main-exec-status-code", "%i",
				s->main_exec_status.code);
			unit_serialize_item_format(u, f,
				"main-exec-status-status", "%i",
				s->main_exec_status.status);
		}
	}
	if (dual_timestamp_is_set(&s->watchdog_timestamp))
		dual_timestamp_serialize(f, "watchdog-timestamp",
			&s->watchdog_timestamp);

	if (s->forbid_restart)
		unit_serialize_item(u, f, "forbid-restart",
			yes_no(s->forbid_restart));

	return 0;
}

static int
service_deserialize_exec_command(Unit *u, const char *key, const char *value)
{
	Service *s = SERVICE(u);
	int r;
	unsigned idx = 0, i;
	bool control, found = false;
	ServiceExecCommand id = _SERVICE_EXEC_COMMAND_INVALID;
	ExecCommand *command = NULL;
	_cleanup_free_ char *args = NULL, *path = NULL;
	_cleanup_strv_free_ char **argv = NULL;

	enum ExecCommandState {
		STATE_EXEC_COMMAND_TYPE,
		STATE_EXEC_COMMAND_INDEX,
		STATE_EXEC_COMMAND_PATH,
		STATE_EXEC_COMMAND_ARGS,
		_STATE_EXEC_COMMAND_MAX,
		_STATE_EXEC_COMMAND_INVALID = -1,
	} state;

	assert(s);
	assert(key);
	assert(value);

	control = streq(key, "control-command");

	state = STATE_EXEC_COMMAND_TYPE;

	for (;;) {
		_cleanup_free_ char *arg = NULL;

		r = extract_first_word(&value, &arg, NULL, EXTRACT_CUNESCAPE);
		if (r == 0)
			break;
		else if (r < 0)
			return r;

		switch (state) {
		case STATE_EXEC_COMMAND_TYPE:
			id = service_exec_command_from_string(arg);
			if (id < 0)
				return -EINVAL;

			state = STATE_EXEC_COMMAND_INDEX;
			break;
		case STATE_EXEC_COMMAND_INDEX:
			r = safe_atou(arg, &idx);
			if (r < 0)
				return -EINVAL;

			state = STATE_EXEC_COMMAND_PATH;
			break;
		case STATE_EXEC_COMMAND_PATH:
			path = arg;
			arg = NULL;
			state = STATE_EXEC_COMMAND_ARGS;

			if (!path_is_absolute(path))
				return -EINVAL;
			break;
		case STATE_EXEC_COMMAND_ARGS:
			r = strv_extend(&argv, arg);
			if (r < 0)
				return -ENOMEM;
			break;
		default:
			assert_not_reached();
			break;
		}
	}

	if (state != STATE_EXEC_COMMAND_ARGS)
		return -EINVAL;

	/* Let's check whether exec command on given offset matches data that we just deserialized */
	for (command = s->exec_command[id], i = 0; command;
		command = command->command_next, i++) {
		if (i != idx)
			continue;

		found = strv_equal(argv, command->argv) &&
			streq(command->path, path);
		break;
	}

	if (!found) {
		/* Command at the index we serialized is different, let's look for command that exactly
                 * matches but is on different index. If there is no such command we will not resume execution. */
		for (command = s->exec_command[id]; command;
			command = command->command_next)
			if (strv_equal(command->argv, argv) &&
				streq(command->path, path))
				break;
	}

	if (command && control) {
		s->control_command = command;
		s->control_command_id = id;
	} else if (command)
		s->main_command = command;
	else
		log_unit_warning(u->id,
			"Current command vanished from the unit file, execution of the command list won't be resumed.");

	return 0;
}

static int
service_deserialize_item(Unit *u, const char *key, const char *value,
	FDSet *fds)
{
	Service *s = SERVICE(u);
	int r;

	assert(u);
	assert(key);
	assert(value);
	assert(fds);

	if (streq(key, "state")) {
		ServiceState state;

		state = service_state_from_string(value);
		if (state < 0)
			log_unit_debug(u->id, "Failed to parse state value %s",
				value);
		else
			s->deserialized_state = state;
	} else if (streq(key, "result")) {
		ServiceResult f;

		f = service_result_from_string(value);
		if (f < 0)
			log_unit_debug(u->id, "Failed to parse result value %s",
				value);
		else if (f != SERVICE_SUCCESS)
			s->result = f;

	} else if (streq(key, "reload-result")) {
		ServiceResult f;

		f = service_result_from_string(value);
		if (f < 0)
			log_unit_debug(u->id,
				"Failed to parse reload result value %s",
				value);
		else if (f != SERVICE_SUCCESS)
			s->reload_result = f;

	} else if (streq(key, "control-pid")) {
		pid_t pid;

		if (parse_pid(value, &pid) < 0)
			log_unit_debug(u->id,
				"Failed to parse control-pid value %s", value);
		else
			s->control_pid = pid;
	} else if (streq(key, "main-pid")) {
		pid_t pid;

		if (parse_pid(value, &pid) < 0)
			log_unit_debug(u->id,
				"Failed to parse main-pid value %s", value);
		else {
			service_set_main_pid(s, pid);
			unit_watch_pid(UNIT(s), pid, false);
		}
	} else if (streq(key, "main-pid-known")) {
		int b;

		b = parse_boolean(value);
		if (b < 0)
			log_unit_debug(u->id,
				"Failed to parse main-pid-known value %s",
				value);
		else
			s->main_pid_known = b;
	} else if (streq(key, "bus-name-good")) {
		int b;

		b = parse_boolean(value);
		if (b < 0)
			log_unit_debug(u->id,
				"Failed to parse bus-name-good value: %s",
				value);
		else
			s->bus_name_good = b;
	} else if (streq(key, "status-text")) {
		char *t;

		t = strdup(value);
		if (!t)
			log_oom();
		else {
			free(s->status_text);
			s->status_text = t;
		}

	} else if (STR_IN_SET(key, "main-command", "control-command")) {
		r = service_deserialize_exec_command(u, key, value);
		if (r < 0)
			log_unit_debug_errno(u->id, r,
				"Failed to parse serialized command \"%s\": %m",
				value);

	} else if (streq(key, "socket-fd")) {
		int fd;

		if (safe_atoi(value, &fd) < 0 || fd < 0 ||
			!fdset_contains(fds, fd))
			log_unit_debug(u->id,
				"Failed to parse socket-fd value %s", value);
		else {
			asynchronous_close(s->socket_fd);
			s->socket_fd = fdset_remove(fds, fd);
		}
	} else if (streq(key, "fd-store-fd")) {
		int fd;

		if (safe_atoi(value, &fd) < 0 || fd < 0 ||
			!fdset_contains(fds, fd))
			log_unit_debug(u->id,
				"Failed to parse fd-store-fd value %s", value);
		else {
			r = service_add_fd_store(s, fd);
			if (r < 0)
				log_unit_error_errno(u->id, r,
					"Failed to add fd to store: %m");
			else if (r > 0)
				fdset_remove(fds, fd);
		}

	} else if (streq(key, "main-exec-status-pid")) {
		pid_t pid;

		if (parse_pid(value, &pid) < 0)
			log_unit_debug(u->id,
				"Failed to parse main-exec-status-pid value %s",
				value);
		else
			s->main_exec_status.pid = pid;
	} else if (streq(key, "main-exec-status-code")) {
		int i;

		if (safe_atoi(value, &i) < 0)
			log_unit_debug(u->id,
				"Failed to parse main-exec-status-code value %s",
				value);
		else
			s->main_exec_status.code = i;
	} else if (streq(key, "main-exec-status-status")) {
		int i;

		if (safe_atoi(value, &i) < 0)
			log_unit_debug(u->id,
				"Failed to parse main-exec-status-status value %s",
				value);
		else
			s->main_exec_status.status = i;
	} else if (streq(key, "main-exec-status-start"))
		dual_timestamp_deserialize(value,
			&s->main_exec_status.start_timestamp);
	else if (streq(key, "main-exec-status-exit"))
		dual_timestamp_deserialize(value,
			&s->main_exec_status.exit_timestamp);
	else if (streq(key, "watchdog-timestamp"))
		dual_timestamp_deserialize(value, &s->watchdog_timestamp);
	else if (streq(key, "forbid-restart")) {
		int b;

		b = parse_boolean(value);
		if (b < 0)
			log_unit_debug(u->id,
				"Failed to parse forbid-restart value %s",
				value);
		else
			s->forbid_restart = b;
	} else
		log_unit_debug(u->id, "Unknown serialization key '%s'", key);

	return 0;
}

_pure_ static UnitActiveState
service_active_state(Unit *u)
{
	const UnitActiveState *table;

	assert(u);

	table = SERVICE(u)->type == SERVICE_IDLE ?
		      state_translation_table_idle :
		      state_translation_table;

	return table[SERVICE(u)->state];
}

static const char *
service_sub_state_to_string(Unit *u)
{
	assert(u);

	return service_state_to_string(SERVICE(u)->state);
}

static bool
service_may_gc(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	/* Never clean up services that still have a process around,
         * even if the service is formally dead. */
	if (cgroup_good(s) > 0 || main_pid_good(s) > 0 ||
		control_pid_good(s) > 0)
		return false;

	return true;
}

_pure_ static bool
service_check_snapshot(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	return s->socket_fd < 0;
}

static int
service_retry_pid_file(Service *s)
{
	int r;

	assert(s->pid_file);
	assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);

	r = service_load_pid_file(s, false);
	if (r < 0)
		return r;

	service_unwatch_pid_file(s);

	service_enter_running(s, SERVICE_SUCCESS);
	return 0;
}

static int
service_watch_pid_file(Service *s)
{
	int r;

	log_unit_debug(UNIT(s)->id, "Setting watch for %s's PID file %s",
		UNIT(s)->id, s->pid_file_pathspec->path);

	r = path_spec_watch(s->pid_file_pathspec, service_dispatch_io);
	if (r < 0)
		goto fail;

	/* the pidfile might have appeared just before we set the watch */
	log_unit_debug(UNIT(s)->id,
		"Trying to read %s's PID file %s in case it changed",
		UNIT(s)->id, s->pid_file_pathspec->path);
	service_retry_pid_file(s);

	return 0;
fail:
	log_unit_error_errno(UNIT(s)->id, r,
		"Failed to set a watch for %s's PID file %s: %m", UNIT(s)->id,
		s->pid_file_pathspec->path);
	service_unwatch_pid_file(s);
	return r;
}

static int
service_demand_pid_file(Service *s)
{
	PathSpec *ps;

	assert(s->pid_file);
	assert(!s->pid_file_pathspec);

	ps = new0(PathSpec, 1);
	if (!ps)
		return -ENOMEM;

	ps->unit = UNIT(s);
	ps->path = strdup(s->pid_file);
	if (!ps->path) {
		free(ps);
		return -ENOMEM;
	}

	path_kill_slashes(ps->path);

	/* PATH_CHANGED would not be enough. There are daemons (sendmail) that
         * keep their PID file open all the time. */
	ps->type = PATH_MODIFIED;
	ps->inotify_fd = -1;

	s->pid_file_pathspec = ps;

	return service_watch_pid_file(s);
}

static int
service_dispatch_io(sd_event_source *source, int fd, uint32_t events,
	void *userdata)
{
	PathSpec *p = userdata;
	Service *s;

	assert(p);

	s = SERVICE(p->unit);

	assert(s);
	assert(fd >= 0);
	assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);
	assert(s->pid_file_pathspec);
	assert(path_spec_owns_inotify_fd(s->pid_file_pathspec, fd));

	log_unit_debug(UNIT(s)->id, "inotify event for %s", UNIT(s)->id);

	if (path_spec_fd_event(p, events) < 0)
		goto fail;

	if (service_retry_pid_file(s) == 0)
		return 0;

	if (service_watch_pid_file(s) < 0)
		goto fail;

	return 0;

fail:
	service_unwatch_pid_file(s);
	service_enter_signal(s, SERVICE_STOP_SIGTERM,
		SERVICE_FAILURE_RESOURCES);
	return 0;
}

static void
service_notify_cgroup_empty_event(Unit *u)
{
	Service *s = SERVICE(u);

	assert(u);

	log_unit_debug(u->id, "%s: cgroup is empty", u->id);

	switch (s->state) {
		/* Waiting for SIGCHLD is usually more interesting,
                 * because it includes return codes/signals. Which is
                 * why we ignore the cgroup events for most cases,
                 * except when we don't know pid which to expect the
                 * SIGCHLD for. */

	case SERVICE_START:
	case SERVICE_START_POST:
		if (s->type == SERVICE_NOTIFY)
			/* No chance of getting a ready notification anymore */
			service_enter_signal(s, SERVICE_FINAL_SIGTERM,
				SERVICE_FAILURE_PROTOCOL);
		else if (s->pid_file_pathspec) {
			/* Give up hoping for the daemon to write its PID file */
			log_unit_warning(u->id,
				"Daemon never wrote its PID file. Failing.");

			service_unwatch_pid_file(s);
			if (s->state == SERVICE_START)
				service_enter_stop_post(s,
					SERVICE_FAILURE_PROTOCOL);
			else
				service_enter_stop(s, SERVICE_FAILURE_PROTOCOL);
		}
		break;

	case SERVICE_RUNNING:
		/* service_enter_running() will figure out what to do */
		service_enter_running(s, SERVICE_SUCCESS);
		break;

	case SERVICE_STOP_SIGABRT:
	case SERVICE_STOP_SIGTERM:
	case SERVICE_STOP_SIGKILL:

		if (main_pid_good(s) <= 0 && !control_pid_good(s))
			service_enter_stop_post(s, SERVICE_SUCCESS);

		break;

	case SERVICE_STOP_POST:
	case SERVICE_FINAL_SIGTERM:
	case SERVICE_FINAL_SIGKILL:
		if (main_pid_good(s) <= 0 && !control_pid_good(s))
			service_enter_dead(s, SERVICE_SUCCESS, true);

		break;

	default:;
	}
}

static void
service_sigchld_event(Unit *u, pid_t pid, int code, int status)
{
	Service *s = SERVICE(u);
	ServiceResult f;

	assert(s);
	assert(pid >= 0);

	if (UNIT(s)->fragment_path ?
			      is_clean_exit(code, status,
				s->type == SERVICE_ONESHOT ?
					      EXIT_CLEAN_COMMAND :
					      EXIT_CLEAN_DAEMON,
				&s->success_status) :
			      is_clean_exit_lsb(code, status, &s->success_status))
		f = SERVICE_SUCCESS;
	else if (code == CLD_EXITED)
		f = SERVICE_FAILURE_EXIT_CODE;
	else if (code == CLD_KILLED)
		f = SERVICE_FAILURE_SIGNAL;
	else if (code == CLD_DUMPED)
		f = SERVICE_FAILURE_CORE_DUMP;
	else
		assert_not_reached();

	/* Here's a special hack: avoid a timing issue caused by switching
         * root when the initramfs contains an old systemd binary.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=1855149
         * https://bugzilla.redhat.com/show_bug.cgi?id=1825232 */
	if (f != SERVICE_SUCCESS && status == SIGTERM &&
		unit_has_name(UNIT(s), SPECIAL_INITRD_SWITCH_ROOT_SERVICE))
		f = SERVICE_SUCCESS;

	if (s->main_pid == pid) {
		/* Forking services may occasionally move to a new PID.
                 * As long as they update the PID file before exiting the old
                 * PID, they're fine. */
		if (service_load_pid_file(s, false) > 0)
			return;

		s->main_pid = 0;
		exec_status_exit(&s->main_exec_status, &s->exec_context, pid,
			code, status);

		if (s->main_command) {
			/* If this is not a forking service than the
                         * main process got started and hence we copy
                         * the exit status so that it is recorded both
                         * as main and as control process exit
                         * status */

			s->main_command->exec_status = s->main_exec_status;

			if (s->main_command->ignore)
				f = SERVICE_SUCCESS;
		} else if (s->exec_command[SERVICE_EXEC_START]) {
			/* If this is a forked process, then we should
                         * ignore the return value if this was
                         * configured for the starter process */

			if (s->exec_command[SERVICE_EXEC_START]->ignore)
				f = SERVICE_SUCCESS;
		}

		log_unit_struct(u->id,
			f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
			LOG_MESSAGE(
				"%s: main process exited, code=%s, status=%i/%s",
				u->id, sigchld_code_to_string(code), status,
				strna(code == CLD_EXITED ?
						      exit_status_to_string(status,
							EXIT_STATUS_FULL) :
						      signal_to_string(status))),
			"EXIT_CODE=%s", sigchld_code_to_string(code),
			"EXIT_STATUS=%i", status, NULL);

		if (f != SERVICE_SUCCESS)
			s->result = f;

		if (s->main_command && s->main_command->command_next &&
			s->type == SERVICE_ONESHOT && f == SERVICE_SUCCESS) {
			/* There is another command to *
                         * execute, so let's do that. */

			log_unit_debug(u->id,
				"%s running next main command for state %s",
				u->id, service_state_to_string(s->state));
			service_run_next_main(s);

		} else {
			/* The service exited, so the service is officially
                         * gone. */
			s->main_command = NULL;

			switch (s->state) {
			case SERVICE_START_POST:
			case SERVICE_RELOAD:
			case SERVICE_STOP:
				/* Need to wait until the operation is
                                 * done */
				break;

			case SERVICE_START:
				if (s->type == SERVICE_ONESHOT) {
					/* This was our main goal, so let's go on */
					if (f == SERVICE_SUCCESS)
						service_enter_start_post(s);
					else
						service_enter_signal(s,
							SERVICE_STOP_SIGTERM,
							f);
					break;
				} else if (s->type == SERVICE_NOTIFY) {
					/* Only enter running through a notification, so that the
                                         * SERVICE_START state signifies that no ready notification
                                         * has been received */
					if (f != SERVICE_SUCCESS)
						service_enter_signal(s,
							SERVICE_STOP_SIGTERM,
							f);
					else if (!s->remain_after_exit)
						/* The service has never been active */
						service_enter_signal(s,
							SERVICE_STOP_SIGTERM,
							SERVICE_FAILURE_PROTOCOL);
					break;
				}

				/* Fall through */

			case SERVICE_RUNNING:
				service_enter_running(s, f);
				break;

			case SERVICE_STOP_SIGABRT:
			case SERVICE_STOP_SIGTERM:
			case SERVICE_STOP_SIGKILL:

				if (!control_pid_good(s))
					service_enter_stop_post(s, f);

				/* If there is still a control process, wait for that first */
				break;

			case SERVICE_STOP_POST:

				if (control_pid_good(s) <= 0)
					service_enter_signal(s,
						SERVICE_FINAL_SIGTERM, f);

				break;

			case SERVICE_FINAL_SIGTERM:
			case SERVICE_FINAL_SIGKILL:

				if (!control_pid_good(s))
					service_enter_dead(s, f, true);
				break;

			default:
				assert_not_reached();
			}
		}

	} else if (s->control_pid == pid) {
		s->control_pid = 0;

		if (s->control_command) {
			exec_status_exit(&s->control_command->exec_status,
				&s->exec_context, pid, code, status);

			if (s->control_command->ignore)
				f = SERVICE_SUCCESS;
		}

		log_unit_full(u->id,
			f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
			"%s: control process exited, code=%s status=%i", u->id,
			sigchld_code_to_string(code), status);

		if (f != SERVICE_SUCCESS)
			s->result = f;

		/* Immediately get rid of the cgroup, so that the
                 * kernel doesn't delay the cgroup empty messages for
                 * the service cgroup any longer than necessary */
		service_kill_control_processes(s);

		if (s->control_command && s->control_command->command_next &&
			f == SERVICE_SUCCESS) {
			/* There is another command to *
                         * execute, so let's do that. */

			log_unit_debug(u->id,
				"%s running next control command for state %s",
				u->id, service_state_to_string(s->state));
			service_run_next_control(s);

		} else {
			/* No further commands for this step, so let's
                         * figure out what to do next */

			s->control_command = NULL;
			s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

			log_unit_debug(u->id,
				"%s got final SIGCHLD for state %s", u->id,
				service_state_to_string(s->state));

			switch (s->state) {
			case SERVICE_START_PRE:
				if (f == SERVICE_SUCCESS)
					service_enter_start(s);
				else
					service_enter_signal(s,
						SERVICE_STOP_SIGTERM, f);
				break;

			case SERVICE_START:
				if (s->type != SERVICE_FORKING)
					/* Maybe spurious event due to a reload that changed the type? */
					break;

				if (f != SERVICE_SUCCESS) {
					service_enter_signal(s,
						SERVICE_STOP_SIGTERM, f);
					break;
				}

				if (s->pid_file) {
					bool has_start_post;
					int r;

					/* Let's try to load the pid file here if we can.
                                         * The PID file might actually be created by a START_POST
                                         * script. In that case don't worry if the loading fails. */

					has_start_post =
						!!s->exec_command
							  [SERVICE_EXEC_START_POST];
					r = service_load_pid_file(s,
						!has_start_post);
					if (!has_start_post && r < 0) {
						r = service_demand_pid_file(s);
						if (r < 0 || !cgroup_good(s))
							service_enter_signal(s,
								SERVICE_STOP_SIGTERM,
								SERVICE_FAILURE_PROTOCOL);
						break;
					}
				} else
					service_search_main_pid(s);

				service_enter_start_post(s);
				break;

			case SERVICE_START_POST:
				if (f != SERVICE_SUCCESS) {
					service_enter_stop(s, f);
					break;
				}

				if (s->pid_file) {
					int r;

					r = service_load_pid_file(s, true);
					if (r < 0) {
						r = service_demand_pid_file(s);
						if (r < 0 || !cgroup_good(s))
							service_enter_stop(s,
								SERVICE_FAILURE_PROTOCOL);
						break;
					}
				} else
					service_search_main_pid(s);

				service_enter_running(s, SERVICE_SUCCESS);
				break;

			case SERVICE_RELOAD:
				if (f == SERVICE_SUCCESS) {
					service_load_pid_file(s, true);
					service_search_main_pid(s);
				}

				s->reload_result = f;
				service_enter_running(s, SERVICE_SUCCESS);
				break;

			case SERVICE_STOP:
				service_enter_signal(s, SERVICE_STOP_SIGTERM,
					f);
				break;

			case SERVICE_STOP_SIGABRT:
			case SERVICE_STOP_SIGTERM:
			case SERVICE_STOP_SIGKILL:
				if (main_pid_good(s) <= 0)
					service_enter_stop_post(s, f);

				/* If there is still a service
                                 * process around, wait until
                                 * that one quit, too */
				break;

			case SERVICE_STOP_POST:
				if (main_pid_good(s) <= 0)
					service_enter_signal(s,
						SERVICE_FINAL_SIGTERM, f);
				break;

			case SERVICE_FINAL_SIGTERM:
			case SERVICE_FINAL_SIGKILL:
				if (main_pid_good(s) <= 0)
					service_enter_dead(s, f, true);
				break;

			default:
				assert_not_reached();
			}
		}
	}

	/* Notify clients about changed exit status */
	unit_add_to_dbus_queue(u);

	/* We got one SIGCHLD for the service, let's watch all
         * processes that are now running of the service, and watch
         * that. Among the PIDs we then watch will be children
         * reassigned to us, which hopefully allows us to identify
         * when all children are gone */
	unit_tidy_watch_pids(u, s->main_pid, s->control_pid);
	unit_watch_all_pids(u);

	/* If the PID set is empty now, then let's finish this off */
	if (set_isempty(u->pids))
		service_notify_cgroup_empty_event(u);
}

static int
service_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata)
{
	Service *s = SERVICE(userdata);

	assert(s);
	assert(source == s->timer_event_source);

	switch (s->state) {
	case SERVICE_START_PRE:
	case SERVICE_START:
		log_unit_warning(UNIT(s)->id,
			"%s %s operation timed out. Terminating.", UNIT(s)->id,
			s->state == SERVICE_START ? "start" : "start-pre");
		service_enter_signal(s, SERVICE_STOP_SIGTERM,
			SERVICE_FAILURE_TIMEOUT);
		break;

	case SERVICE_START_POST:
		log_unit_warning(UNIT(s)->id,
			"%s start-post operation timed out. Stopping.",
			UNIT(s)->id);
		service_enter_stop(s, SERVICE_FAILURE_TIMEOUT);
		break;

	case SERVICE_RELOAD:
		log_unit_warning(UNIT(s)->id,
			"%s reload operation timed out. Stopping.",
			UNIT(s)->id);
		s->reload_result = SERVICE_FAILURE_TIMEOUT;
		service_enter_running(s, SERVICE_SUCCESS);
		break;

	case SERVICE_STOP:
		log_unit_warning(UNIT(s)->id,
			"%s stopping timed out. Terminating.", UNIT(s)->id);
		service_enter_signal(s, SERVICE_STOP_SIGTERM,
			SERVICE_FAILURE_TIMEOUT);
		break;

	case SERVICE_STOP_SIGABRT:
		log_unit_warning(UNIT(s)->id,
			"%s stop-sigabrt timed out. Terminating.", UNIT(s)->id);
		service_enter_signal(s, SERVICE_STOP_SIGTERM, s->result);
		break;

	case SERVICE_STOP_SIGTERM:
		if (s->kill_context.send_sigkill) {
			log_unit_warning(UNIT(s)->id,
				"%s stop-sigterm timed out. Killing.",
				UNIT(s)->id);
			service_enter_signal(s, SERVICE_STOP_SIGKILL,
				SERVICE_FAILURE_TIMEOUT);
		} else {
			log_unit_warning(UNIT(s)->id,
				"%s stop-sigterm timed out. Skipping SIGKILL.",
				UNIT(s)->id);
			service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
		}

		break;

	case SERVICE_STOP_SIGKILL:
		/* Uh, we sent a SIGKILL and it is still not gone?
                 * Must be something we cannot kill, so let's just be
                 * weirded out and continue */

		log_unit_warning(UNIT(s)->id,
			"%s still around after SIGKILL. Ignoring.",
			UNIT(s)->id);
		service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
		break;

	case SERVICE_STOP_POST:
		log_unit_warning(UNIT(s)->id,
			"%s stop-post timed out. Terminating.", UNIT(s)->id);
		service_enter_signal(s, SERVICE_FINAL_SIGTERM,
			SERVICE_FAILURE_TIMEOUT);
		break;

	case SERVICE_FINAL_SIGTERM:
		if (s->kill_context.send_sigkill) {
			log_unit_warning(UNIT(s)->id,
				"%s stop-final-sigterm timed out. Killing.",
				UNIT(s)->id);
			service_enter_signal(s, SERVICE_FINAL_SIGKILL,
				SERVICE_FAILURE_TIMEOUT);
		} else {
			log_unit_warning(UNIT(s)->id,
				"%s stop-final-sigterm timed out. Skipping SIGKILL. Entering failed mode.",
				UNIT(s)->id);
			service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
		}

		break;

	case SERVICE_FINAL_SIGKILL:
		log_unit_warning(UNIT(s)->id,
			"%s still around after final SIGKILL. Entering failed mode.",
			UNIT(s)->id);
		service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, true);
		break;

	case SERVICE_AUTO_RESTART:
		log_unit_info(UNIT(s)->id,
			s->restart_usec > 0 ?
				      "%s holdoff time over, scheduling restart." :
				      "%s has no holdoff time, scheduling restart.",
			UNIT(s)->id);
		service_enter_restart(s);
		break;

	default:
		assert_not_reached();
	}

	return 0;
}

static int
service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata)
{
	Service *s = SERVICE(userdata);
	char t[FORMAT_TIMESPAN_MAX];

	assert(s);
	assert(source == s->watchdog_event_source);

	log_unit_error(UNIT(s)->id, "%s watchdog timeout (limit %s)!",
		UNIT(s)->id,
		format_timespan(t, sizeof(t), s->watchdog_usec, 1));

	service_enter_signal(s, SERVICE_STOP_SIGABRT, SERVICE_FAILURE_WATCHDOG);

	return 0;
}

static bool
service_notify_message_authorized(Service *s, pid_t pid, char **tags,
	FDSet *fds)
{
	assert(s);

	if (s->notify_access == NOTIFY_NONE) {
		log_unit_warning(UNIT(s)->id,
			"Got notification message from PID " PID_FMT
			", but reception is disabled.",
			pid);
		return false;
	}

	if (s->notify_access == NOTIFY_MAIN && pid != s->main_pid) {
		if (s->main_pid != 0)
			log_unit_warning(UNIT(s)->id,
				"Got notification message from PID " PID_FMT
				", but reception only permitted for main PID " PID_FMT,
				pid, s->main_pid);
		else
			log_unit_warning(UNIT(s)->id,
				"Got notification message from PID " PID_FMT
				", but reception only permitted for main PID which is currently not known",
				pid);

		return false;
	}

	return true;
}

static void
service_notify_message(Unit *u, const struct socket_ucred *ucred, char **tags,
	FDSet *fds)
{
	Service *s = SERVICE(u);
	bool notify_dbus = false;
	const char *e;
	int r;

	assert(u);
	assert(ucred);

	if (!service_notify_message_authorized(SERVICE(u), ucred->pid, tags,
		    fds))
		return;

	if (_unlikely_(log_get_max_level() >= LOG_DEBUG)) {
		_cleanup_free_ char *cc = NULL;

		cc = strv_join(tags, ", ");
		log_unit_debug(u->id,
			"Got notification message from PID " PID_FMT " (%s)",
			ucred->pid, isempty(cc) ? "n/a" : cc);
	}

	/* Interpret MAINPID= */
	e = strv_find_startswith(tags, "MAINPID=");
	if (e &&
		IN_SET(s->state, SERVICE_START, SERVICE_START_POST,
			SERVICE_RUNNING, SERVICE_RELOAD)) {
		pid_t new_main_pid;

		if (parse_pid(e, &new_main_pid) < 0)
			log_unit_warning(u->id,
				"Failed to parse MAINPID= field in notification message, ignoring: %s",
				e);
		else if (!s->main_pid_known || new_main_pid != s->main_pid) {
			r = service_is_suitable_main_pid(s, new_main_pid,
				LOG_WARNING);
			if (r == 0) {
				/* The new main PID is a bit suspicous, which is OK if the sender is privileged. */

				if (ucred->uid == 0) {
					log_unit_debug(u->id,
						"New main PID " PID_FMT
						" does not belong to service, but we'll accept it as the request to change it came from a privileged process.",
						new_main_pid);
					r = 1;
				} else
					log_unit_debug(u->id,
						"New main PID " PID_FMT
						" does not belong to service, refusing.",
						new_main_pid);
			}
			if (r > 0) {
				service_set_main_pid(s, new_main_pid);
				unit_watch_pid(UNIT(s), new_main_pid, false);
				notify_dbus = true;
			}
		}
	}

	/* Interpret RELOADING= */
	if (strv_find(tags, "RELOADING=1")) {
		log_unit_debug(u->id, "%s: got RELOADING=1", u->id);
		s->notify_state = NOTIFY_RELOADING;

		if (s->state == SERVICE_RUNNING)
			service_enter_reload_by_notify(s);

		notify_dbus = true;
	}

	/* Interpret READY= */
	if (strv_find(tags, "READY=1")) {
		log_unit_debug(u->id, "%s: got READY=1", u->id);
		s->notify_state = NOTIFY_READY;

		/* Type=notify services inform us about completed
                 * initialization with READY=1 */
		if (s->type == SERVICE_NOTIFY && s->state == SERVICE_START)
			service_enter_start_post(s);

		/* Sending READY=1 while we are reloading informs us
                 * that the reloading is complete */
		if (s->state == SERVICE_RELOAD && s->control_pid == 0)
			service_enter_running(s, SERVICE_SUCCESS);

		notify_dbus = true;
	}

	/* Interpret STOPPING= */
	if (strv_find(tags, "STOPPING=1")) {
		log_unit_debug(u->id, "%s: got STOPPING=1", u->id);
		s->notify_state = NOTIFY_STOPPING;

		if (s->state == SERVICE_RUNNING)
			service_enter_stop_by_notify(s);

		notify_dbus = true;
	}

	/* Interpret STATUS= */
	e = strv_find_startswith(tags, "STATUS=");
	if (e) {
		_cleanup_free_ char *t = NULL;

		if (!isempty(e)) {
			/* Note that this size limit check is mostly paranoia: since the datagram size we are willing
                         * to process is already limited to NOTIFY_BUFFER_MAX, this limit here should never be hit. */
			if (strlen(e) > STATUS_TEXT_MAX)
				log_unit_warning(u->id,
					"Status message overly long (%zu > %u), ignoring.",
					strlen(e), STATUS_TEXT_MAX);
			else if (!utf8_is_valid(e))
				log_unit_warning(u->id,
					"Status message in notification message is not UTF-8 clean, ignoring.");
			else {
				log_unit_debug(u->id, "%s: got STATUS=%s",
					u->id, e);

				t = strdup(e);
				if (!t)
					log_oom();
			}
		}

		if (!streq_ptr(s->status_text, t)) {
			free(s->status_text);
			s->status_text = t;
			t = NULL;

			notify_dbus = true;
		}
	}

	/* Interpret ERRNO= */
	e = strv_find_startswith(tags, "ERRNO=");
	if (e) {
		int status_errno;

		if (safe_atoi(e, &status_errno) < 0 || status_errno < 0)
			log_unit_warning(u->id,
				"Failed to parse ERRNO= field in notification message: %s",
				e);
		else {
			log_unit_debug(u->id, "%s: got ERRNO=%s", u->id, e);

			if (s->status_errno != status_errno) {
				s->status_errno = status_errno;
				notify_dbus = true;
			}
		}
	}

	/* Interpret WATCHDOG= */
	if (strv_find(tags, "WATCHDOG=1")) {
		log_unit_debug(u->id, "%s: got WATCHDOG=1", u->id);
		service_reset_watchdog(s);
	}

	/* Add the passed fds to the fd store */
	if (strv_find(tags, "FDSTORE=1")) {
		log_unit_debug(u->id, "%s: got FDSTORE=1", u->id);
		service_add_fd_store_set(s, fds);
	}

	/* Notify clients about changed status or main pid */
	if (notify_dbus)
		unit_add_to_dbus_queue(u);
}

static int
service_get_timeout(Unit *u, uint64_t *timeout)
{
	Service *s = SERVICE(u);
	int r;

	if (!s->timer_event_source)
		return 0;

	r = sd_event_source_get_time(s->timer_event_source, timeout);
	if (r < 0)
		return r;

	return 1;
}

static void
service_bus_name_owner_change(Unit *u, const char *name, const char *old_owner,
	const char *new_owner)
{
	Service *s = SERVICE(u);
	int r;

	assert(s);
	assert(name);

	assert(streq(s->bus_name, name));
	assert(old_owner || new_owner);

	if (old_owner && new_owner)
		log_unit_debug(u->id,
			"%s's D-Bus name %s changed owner from %s to %s", u->id,
			name, old_owner, new_owner);
	else if (old_owner)
		log_unit_debug(u->id,
			"%s's D-Bus name %s no longer registered by %s", u->id,
			name, old_owner);
	else
		log_unit_debug(u->id, "%s's D-Bus name %s now registered by %s",
			u->id, name, new_owner);

	s->bus_name_good = !!new_owner;

	if (s->type == SERVICE_DBUS) {
		/* service_enter_running() will figure out what to
                 * do */
		if (s->state == SERVICE_RUNNING)
			service_enter_running(s, SERVICE_SUCCESS);
		else if (s->state == SERVICE_START && new_owner)
			service_enter_start_post(s);

	} else if (new_owner && s->main_pid <= 0 &&
		(s->state == SERVICE_START || s->state == SERVICE_START_POST ||
			s->state == SERVICE_RUNNING ||
			s->state == SERVICE_RELOAD)) {
		_cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
		pid_t pid;

		/* Try to acquire PID from bus service */

		r = sd_bus_get_name_creds(u->manager->api_bus, name,
			SD_BUS_CREDS_PID, &creds);
		if (r >= 0)
			r = sd_bus_creds_get_pid(creds, &pid);
		if (r >= 0) {
			log_unit_debug(u->id,
				"%s's D-Bus name %s is now owned by process %u",
				u->id, name, (unsigned)pid);

			service_set_main_pid(s, pid);
			unit_watch_pid(UNIT(s), pid, false);
		}
	}
}

int
service_set_socket_fd(Service *s, int fd, Socket *sock,
	bool selinux_context_net)
{
	_cleanup_free_ char *peer = NULL;
	int r;

	assert(s);
	assert(fd >= 0);

	/* This is called by the socket code when instantiating a new
         * service for a stream socket and the socket needs to be
         * configured. */

	if (UNIT(s)->load_state != UNIT_LOADED)
		return -EINVAL;

	if (s->socket_fd >= 0)
		return -EBUSY;

	if (s->state != SERVICE_DEAD)
		return -EAGAIN;

	if (getpeername_pretty(fd, true, &peer) >= 0) {
		if (UNIT(s)->description) {
			_cleanup_free_ char *a;

			a = strjoin(UNIT(s)->description, " (", peer, ")",
				NULL);
			if (!a)
				return -ENOMEM;

			r = unit_set_description(UNIT(s), a);
		} else
			r = unit_set_description(UNIT(s), peer);

		if (r < 0)
			return r;
	}

	s->socket_fd = fd;
	s->socket_fd_selinux_context_net = selinux_context_net;

	unit_ref_set(&s->accept_socket, UNIT(s), UNIT(sock));

	return unit_add_two_dependencies(UNIT(sock), UNIT_BEFORE, UNIT_TRIGGERS,
		UNIT(s), false);
}

static void
service_reset_failed(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	if (s->state == SERVICE_FAILED)
		service_set_state(s, SERVICE_DEAD);

	s->result = SERVICE_SUCCESS;
	s->reload_result = SERVICE_SUCCESS;

	RATELIMIT_RESET(s->start_limit);
}

static int
service_kill(Unit *u, KillWho who, int signo, sd_bus_error *error)
{
	Service *s = SERVICE(u);

	return unit_kill_common(u, who, signo, s->main_pid, s->control_pid,
		error);
}

static const char *const service_state_table[_SERVICE_STATE_MAX] = {
	[SERVICE_DEAD] = "dead",
	[SERVICE_START_PRE] = "start-pre",
	[SERVICE_START] = "start",
	[SERVICE_START_POST] = "start-post",
	[SERVICE_RUNNING] = "running",
	[SERVICE_EXITED] = "exited",
	[SERVICE_RELOAD] = "reload",
	[SERVICE_STOP] = "stop",
	[SERVICE_STOP_SIGABRT] = "stop-sigabrt",
	[SERVICE_STOP_SIGTERM] = "stop-sigterm",
	[SERVICE_STOP_SIGKILL] = "stop-sigkill",
	[SERVICE_STOP_POST] = "stop-post",
	[SERVICE_FINAL_SIGTERM] = "final-sigterm",
	[SERVICE_FINAL_SIGKILL] = "final-sigkill",
	[SERVICE_FAILED] = "failed",
	[SERVICE_AUTO_RESTART] = "auto-restart",
};

DEFINE_STRING_TABLE_LOOKUP(service_state, ServiceState);

static int
service_main_pid(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	return s->main_pid;
}

static int
service_control_pid(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	return s->control_pid;
}

static bool
service_needs_console(Unit *u)
{
	Service *s = SERVICE(u);

	assert(s);

	/* We provide our own implementation of this here, instead of relying of the generic implementation
         * unit_needs_console() provides, since we want to return false if we are in SERVICE_EXITED state. */

	if (!exec_context_may_touch_console(&s->exec_context))
		return false;

	return IN_SET(s->state, SERVICE_START_PRE, SERVICE_START,
		SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD,
		SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM,
		SERVICE_STOP_SIGKILL, SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM,
		SERVICE_FINAL_SIGKILL);
}

static const char *const service_restart_table[_SERVICE_RESTART_MAX] = {
	[SERVICE_RESTART_NO] = "no",
	[SERVICE_RESTART_ON_SUCCESS] = "on-success",
	[SERVICE_RESTART_ON_FAILURE] = "on-failure",
	[SERVICE_RESTART_ON_ABNORMAL] = "on-abnormal",
	[SERVICE_RESTART_ON_WATCHDOG] = "on-watchdog",
	[SERVICE_RESTART_ON_ABORT] = "on-abort",
	[SERVICE_RESTART_ALWAYS] = "always",
};

DEFINE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

static const char *const service_type_table[_SERVICE_TYPE_MAX] = {
	[SERVICE_SIMPLE] = "simple",
	[SERVICE_FORKING] = "forking",
	[SERVICE_ONESHOT] = "oneshot",
	[SERVICE_DBUS] = "dbus",
	[SERVICE_NOTIFY] = "notify",
	[SERVICE_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char *const service_exec_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
	[SERVICE_EXEC_START_PRE] = "ExecStartPre",
	[SERVICE_EXEC_START] = "ExecStart",
	[SERVICE_EXEC_START_POST] = "ExecStartPost",
	[SERVICE_EXEC_RELOAD] = "ExecReload",
	[SERVICE_EXEC_STOP] = "ExecStop",
	[SERVICE_EXEC_STOP_POST] = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

static const char *const notify_access_table[_NOTIFY_ACCESS_MAX] = {
	[NOTIFY_NONE] = "none",
	[NOTIFY_MAIN] = "main",
	[NOTIFY_ALL] = "all"
};

DEFINE_STRING_TABLE_LOOKUP(notify_access, NotifyAccess);

static const char *const notify_state_table[_NOTIFY_STATE_MAX] = {
	[NOTIFY_UNKNOWN] = "unknown",
	[NOTIFY_READY] = "ready",
	[NOTIFY_RELOADING] = "reloading",
	[NOTIFY_STOPPING] = "stopping",
};

DEFINE_STRING_TABLE_LOOKUP(notify_state, NotifyState);

static const char *const service_result_table[_SERVICE_RESULT_MAX] = {
	[SERVICE_SUCCESS] = "success",
	[SERVICE_FAILURE_RESOURCES] = "resources",
	[SERVICE_FAILURE_PROTOCOL] = "protocol",
	[SERVICE_FAILURE_TIMEOUT] = "timeout",
	[SERVICE_FAILURE_EXIT_CODE] = "exit-code",
	[SERVICE_FAILURE_SIGNAL] = "signal",
	[SERVICE_FAILURE_CORE_DUMP] = "core-dump",
	[SERVICE_FAILURE_WATCHDOG] = "watchdog",
	[SERVICE_FAILURE_START_LIMIT] = "start-limit"
};

DEFINE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),
        .exec_context_offset = offsetof(Service, exec_context),
        .cgroup_context_offset = offsetof(Service, cgroup_context),
        .kill_context_offset = offsetof(Service, kill_context),
        .exec_runtime_offset = offsetof(Service, exec_runtime),

        .sections =
                "Unit\0"
                "Service\0"
                "Install\0",
        .private_section = "Service",

        .init = service_init,
        .done = service_done,
        .load = service_load,
        .release_resources = service_release_resources,

        .coldplug = service_coldplug,

        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .can_reload = service_can_reload,

        .kill = service_kill,

        .serialize = service_serialize,
        .deserialize_item = service_deserialize_item,

        .active_state = service_active_state,
        .sub_state_to_string = service_sub_state_to_string,

        .may_gc = service_may_gc,
        .check_snapshot = service_check_snapshot,

        .sigchld_event = service_sigchld_event,

        .reset_failed = service_reset_failed,

        .notify_cgroup_empty = service_notify_cgroup_empty_event,
        .notify_message = service_notify_message,

        .main_pid = service_main_pid,
        .control_pid = service_control_pid,

        .bus_name_owner_change = service_bus_name_owner_change,

        .bus_interface = SVC_DBUS_INTERFACE ".Service",
        .bus_vtable = bus_service_vtable,
        .bus_set_property = bus_service_set_property,
        .bus_commit_properties = bus_service_commit_properties,

        .get_timeout = service_get_timeout,
        .needs_console = service_needs_console,
        .can_transient = true,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Starting %s...",
                        [1] = "Stopping %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Started %s.",
                        [JOB_FAILED]     = "Failed to start %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped %s.",
                        [JOB_FAILED]     = "Stopped (with error) %s.",
                },
        },
};
