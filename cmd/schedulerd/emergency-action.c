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
#include "raw-reboot.h"
#include "reboot-util.h"
#include "special.h"
#include "string-table.h"
#include "virt.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/reboot.h>
#endif

static const char* const emergency_action_table[_EMERGENCY_ACTION_MAX] = {
        [EMERGENCY_ACTION_NONE]               = "none",
        [EMERGENCY_ACTION_EXIT]               = "exit",
        [EMERGENCY_ACTION_EXIT_FORCE]         = "exit-force",
        [EMERGENCY_ACTION_REBOOT]             = "reboot",
        [EMERGENCY_ACTION_REBOOT_FORCE]       = "reboot-force",
        [EMERGENCY_ACTION_REBOOT_IMMEDIATE]   = "reboot-immediate",
        [EMERGENCY_ACTION_POWEROFF]           = "poweroff",
        [EMERGENCY_ACTION_POWEROFF_FORCE]     = "poweroff-force",
        [EMERGENCY_ACTION_POWEROFF_IMMEDIATE] = "poweroff-immediate",
        [EMERGENCY_ACTION_SOFT_REBOOT]        = "soft-reboot",
        [EMERGENCY_ACTION_SOFT_REBOOT_FORCE]  = "soft-reboot-force",
        [EMERGENCY_ACTION_KEXEC]              = "kexec",
        [EMERGENCY_ACTION_KEXEC_FORCE]        = "kexec-force",
        [EMERGENCY_ACTION_HALT]               = "halt",
        [EMERGENCY_ACTION_HALT_FORCE]         = "halt-force",
        [EMERGENCY_ACTION_HALT_IMMEDIATE]     = "halt-immediate",
};

static void log_and_status(Manager *m, bool warn, const char *message, const char *reason) {
        log_full(warn ? LOG_WARNING : LOG_DEBUG, "%s: %s", message, reason);
        if (warn)
                manager_status_printf(m, STATUS_TYPE_EMERGENCY,
                                      ANSI_HIGHLIGHT_RED "  !!  " ANSI_NORMAL,
                                      "%s: %s", message, reason);
}

void emergency_action(
                Manager *m,
                EmergencyAction action,
                EmergencyActionFlags options,
                const char *reboot_arg,
                int exit_status,
                const char *reason) {

        Unit *u;

        assert(m);
        assert(action >= 0);
        assert(action < _EMERGENCY_ACTION_MAX);

        /* Is the special shutdown target active or queued? If so, we are in shutdown state */
        if (IN_SET(action,
                   EMERGENCY_ACTION_REBOOT,
                   EMERGENCY_ACTION_SOFT_REBOOT,
                   EMERGENCY_ACTION_POWEROFF,
                   EMERGENCY_ACTION_EXIT,
                   EMERGENCY_ACTION_KEXEC,
                   EMERGENCY_ACTION_HALT)) {
                u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
                if (u && unit_active_or_pending(u)) {
                        log_notice("Shutdown is already active. Skipping emergency action request %s.",
                                   emergency_action_table[action]);
                        return;
                }
        }

        if (action == EMERGENCY_ACTION_NONE)
                return;

#ifdef SVC_PLATFORM_Linux
        // HACK: No watchdog?
        // if (FLAGS_SET(options, EMERGENCY_ACTION_IS_WATCHDOG) && !m->service_watchdogs) {
        //         log_warning("Watchdog disabled! Not acting on: %s", reason);
        //         return;
        // }

        bool warn = FLAGS_SET(options, EMERGENCY_ACTION_WARN);

        switch (action) {

        case EMERGENCY_ACTION_REBOOT:
                log_and_status(m, warn, "Rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_REBOOT_FORCE:
                log_and_status(m, warn, "Forcibly rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                m->objective = MANAGER_REBOOT;
                break;

        case EMERGENCY_ACTION_REBOOT_IMMEDIATE:
                log_and_status(m, warn, "Rebooting immediately", reason);

                sync();

                if (!isempty(reboot_arg)) {
                        log_info("Rebooting with argument '%s'.", reboot_arg);
                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, reboot_arg);
                        log_warning_errno(errno, "Failed to reboot with parameter, retrying without: %m");
                }

                log_info("Rebooting.");
                (void) reboot(RB_AUTOBOOT);
                break;

        case EMERGENCY_ACTION_SOFT_REBOOT:
                log_and_status(m, warn, "Soft-rebooting", reason);

                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_SOFT_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_SOFT_REBOOT_FORCE:
                log_and_status(m, warn, "Forcibly soft-rebooting", reason);

                m->objective = MANAGER_SOFT_REBOOT;
                break;

        case EMERGENCY_ACTION_EXIT:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, warn, "Exiting", reason);
                        (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_EXIT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                        break;
                }

                log_notice("Doing \"poweroff\" action instead of an \"exit\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF:
                log_and_status(m, warn, "Powering off", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_POWEROFF_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_EXIT_FORCE:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, warn, "Exiting immediately", reason);
                        m->objective = MANAGER_EXIT;
                        break;
                }

                log_notice("Doing \"poweroff-force\" action instead of an \"exit-force\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF_FORCE:
                log_and_status(m, warn, "Forcibly powering off", reason);
                m->objective = MANAGER_POWEROFF;
                break;

        case EMERGENCY_ACTION_POWEROFF_IMMEDIATE:
                log_and_status(m, warn, "Powering off immediately", reason);

                sync();

                log_info("Powering off.");
                (void) reboot(RB_POWER_OFF);
                break;

        case EMERGENCY_ACTION_KEXEC:
                log_and_status(m, warn, "Executing kexec", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_KEXEC_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_KEXEC_FORCE:
                log_and_status(m, warn, "Forcibly executing kexec", reason);
                m->objective = MANAGER_KEXEC;
                break;

        case EMERGENCY_ACTION_HALT:
                log_and_status(m, warn, "Halting", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_HALT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_HALT_FORCE:
                log_and_status(m, warn, "Forcibly halting", reason);
                m->objective = MANAGER_HALT;
                break;

        case EMERGENCY_ACTION_HALT_IMMEDIATE:
                log_and_status(m, warn, "Halting immediately", reason);

                sync();

                log_info("Halting.");
                (void) reboot(RB_HALT_SYSTEM);
                break;

        default:
                assert_not_reached();
        }
#else
	log_and_status(m, "Carrying out an emergency action", reason);
	abort();
#endif
}

DEFINE_STRING_TABLE_LOOKUP(emergency_action, EmergencyAction);
