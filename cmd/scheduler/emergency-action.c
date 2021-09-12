/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering
  Copyright 2012 Michael Olbrich

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

#include <sys/reboot.h>
#include <sys/syscall.h>

#include "bus-error.h"
#include "bus-util.h"
#include "emergency-action.h"
#include "special.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/reboot.h>
#endif

static void
log_and_status(Manager *m, const char *message, const char *reason)
{
	log_warning("%s: %s", message, reason);
	manager_status_printf(m, STATUS_TYPE_EMERGENCY,
		ANSI_HIGHLIGHT_RED_ON " !!  " ANSI_HIGHLIGHT_OFF, "%s: %s",
		message, reason);
}

int
emergency_action(Manager *m, EmergencyAction action, const char *reboot_arg,
	const char *reason)
{
	int r;

	assert(m);
	assert(action >= 0);
	assert(action < _EMERGENCY_ACTION_MAX);

	if (action == EMERGENCY_ACTION_NONE)
		return -ECANCELED;

	if (m->running_as == SYSTEMD_USER) {
		/* Downgrade all options to simply exiting if we run
                 * in user mode */

		log_warning("Exiting: %s", reason);
		m->exit_code = MANAGER_EXIT;
		return -ECANCELED;
	}

#ifdef SVC_PLATFORM_Linux
	switch (action) {
	case EMERGENCY_ACTION_REBOOT: {
		_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

		log_and_status(m, "Rebooting", reason);

		update_reboot_param_file(reboot_arg);
		r = manager_add_job_by_name(m, JOB_START, SPECIAL_REBOOT_TARGET,
			JOB_REPLACE, true, &error, NULL);
		if (r < 0)
			log_error("Failed to reboot: %s.",
				bus_error_message(&error, r));

		break;
	}

	case EMERGENCY_ACTION_REBOOT_FORCE:
		log_and_status(m, "Forcibly rebooting", reason);

		update_reboot_param_file(reboot_arg);
		m->exit_code = MANAGER_REBOOT;
		break;

	case EMERGENCY_ACTION_REBOOT_IMMEDIATE:
		log_and_status(m, "Rebooting immediately", reason);

		sync();

		if (reboot_arg) {
			log_info("Rebooting with argument '%s'.", reboot_arg);
			syscall(SYS_reboot, LINUX_REBOOT_MAGIC1,
				LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2,
				reboot_arg);
		}

		log_info("Rebooting.");
		bsd_reboot(RB_AUTOBOOT);
		break;

	case EMERGENCY_ACTION_POWEROFF: {
		_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

		log_and_status(m, "Powering off", reason);

		r = manager_add_job_by_name(m, JOB_START,
			SPECIAL_POWEROFF_TARGET, JOB_REPLACE, true, &error,
			NULL);
		if (r < 0)
			log_error("Failed to poweroff: %s.",
				bus_error_message(&error, r));

		break;
	}

	case EMERGENCY_ACTION_POWEROFF_FORCE:
		log_and_status(m, "Forcibly powering off", reason);
		m->exit_code = MANAGER_POWEROFF;
		break;

	case EMERGENCY_ACTION_POWEROFF_IMMEDIATE:
		log_and_status(m, "Powering off immediately", reason);

		sync();

		log_info("Powering off.");
		bsd_reboot(RB_POWER_OFF);
		break;

	default:
		assert_not_reached("Unknown emergency action");
	}

	return -ECANCELED;
#else
	log_and_status(m, "Carrying out an emergency action", reason);
	abort();
#endif
}

static const char *const emergency_action_table[_EMERGENCY_ACTION_MAX] = {
	[EMERGENCY_ACTION_NONE] = "none",
	[EMERGENCY_ACTION_REBOOT] = "reboot",
	[EMERGENCY_ACTION_REBOOT_FORCE] = "reboot-force",
	[EMERGENCY_ACTION_REBOOT_IMMEDIATE] = "reboot-immediate",
	[EMERGENCY_ACTION_POWEROFF] = "poweroff",
	[EMERGENCY_ACTION_POWEROFF_FORCE] = "poweroff-force",
	[EMERGENCY_ACTION_POWEROFF_IMMEDIATE] = "poweroff-immediate"
};
DEFINE_STRING_TABLE_LOOKUP(emergency_action, EmergencyAction);
