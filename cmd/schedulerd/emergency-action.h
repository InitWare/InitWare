#pragma once

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

#include <errno.h>

typedef enum EmergencyAction {
        EMERGENCY_ACTION_NONE,
        EMERGENCY_ACTION_EXIT,
        EMERGENCY_ACTION_EXIT_FORCE,
        _EMERGENCY_ACTION_LAST_USER_ACTION = EMERGENCY_ACTION_EXIT_FORCE,
        EMERGENCY_ACTION_REBOOT,
        EMERGENCY_ACTION_REBOOT_FORCE,
        EMERGENCY_ACTION_REBOOT_IMMEDIATE,
        EMERGENCY_ACTION_POWEROFF,
        EMERGENCY_ACTION_POWEROFF_FORCE,
        EMERGENCY_ACTION_POWEROFF_IMMEDIATE,
        EMERGENCY_ACTION_SOFT_REBOOT,
        EMERGENCY_ACTION_SOFT_REBOOT_FORCE,
        EMERGENCY_ACTION_KEXEC,
        EMERGENCY_ACTION_KEXEC_FORCE,
        EMERGENCY_ACTION_HALT,
        EMERGENCY_ACTION_HALT_FORCE,
        EMERGENCY_ACTION_HALT_IMMEDIATE,
        _EMERGENCY_ACTION_MAX,
        _EMERGENCY_ACTION_INVALID = -EINVAL,
} EmergencyAction;

typedef enum EmergencyActionFlags {
        EMERGENCY_ACTION_IS_WATCHDOG = 1 << 0,
        EMERGENCY_ACTION_WARN        = 1 << 1,
} EmergencyActionFlags;

#include "macro.h"
#include "manager.h"

void emergency_action(Manager *m,
                      EmergencyAction action, EmergencyActionFlags options,
                      const char *reboot_arg, int exit_status, const char *reason);

const char *emergency_action_to_string(EmergencyAction i) _const_;
EmergencyAction emergency_action_from_string(const char *s) _pure_;
