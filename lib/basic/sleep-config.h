/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#pragma once

#include <stdbool.h>

typedef enum SleepOperation {
        SLEEP_SUSPEND,
        SLEEP_HIBERNATE,
        SLEEP_HYBRID_SLEEP,
        _SLEEP_OPERATION_CONFIG_MAX,
        /* The operations above require configuration for mode and state. The ones below are "combined"
         * operations that use config from those individual operations. */

        SLEEP_SUSPEND_THEN_HIBERNATE,

        _SLEEP_OPERATION_MAX,
        _SLEEP_OPERATION_INVALID = -EINVAL,
} SleepOperation;

static inline bool SLEEP_OPERATION_IS_HIBERNATION(SleepOperation operation) {
        return IN_SET(operation, SLEEP_HIBERNATE, SLEEP_HYBRID_SLEEP);
}

typedef struct SleepConfig {
        bool allow[_SLEEP_OPERATION_MAX];

        char **states[_SLEEP_OPERATION_CONFIG_MAX];
        char **modes[_SLEEP_OPERATION_CONFIG_MAX];  /* Power mode after writing hibernation image (/sys/power/disk) */
        char **mem_modes;                           /* /sys/power/mem_sleep */

        usec_t hibernate_delay_usec;
        usec_t suspend_estimation_usec;
} SleepConfig;

SleepConfig* sleep_config_free(SleepConfig *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(SleepConfig*, sleep_config_free);

int parse_sleep_config(SleepConfig **sleep_config);

typedef enum SleepSupport {
        SLEEP_SUPPORTED,
        SLEEP_DISABLED,                    /* Disabled in SleepConfig.allow */
        SLEEP_NOT_CONFIGURED,              /* SleepConfig.states is not configured */
        SLEEP_STATE_OR_MODE_NOT_SUPPORTED, /* SleepConfig.states/modes are not supported by kernel */
        SLEEP_RESUME_NOT_SUPPORTED,
        SLEEP_RESUME_DEVICE_MISSING,       /* resume= is specified, but the device cannot be found in /proc/swaps */
        SLEEP_RESUME_MISCONFIGURED,        /* resume= is not set yet resume_offset= is configured */
        SLEEP_NOT_ENOUGH_SWAP_SPACE,
        SLEEP_ALARM_NOT_SUPPORTED,         /* CLOCK_BOOTTIME_ALARM is unsupported by kernel (only used by s2h) */
} SleepSupport;

int sleep_supported_full(SleepOperation operation, SleepSupport *ret_support);
static inline int sleep_supported(SleepOperation operation) {
        return sleep_supported_full(operation, NULL);
}
