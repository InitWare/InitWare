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

#include <stdio.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "extract-word.h"
#include "fileio.h"
#include "log.h"
#include "path-util.h"
#include "sleep-config.h"
#include "string-table.h"
#include "strv.h"
#include "util.h"

#define DEFAULT_SUSPEND_ESTIMATION_USEC (1 * USEC_PER_HOUR)

static const char* const sleep_operation_table[_SLEEP_OPERATION_MAX] = {
        [SLEEP_SUSPEND]                = "suspend",
        [SLEEP_HIBERNATE]              = "hibernate",
        [SLEEP_HYBRID_SLEEP]           = "hybrid-sleep",
        [SLEEP_SUSPEND_THEN_HIBERNATE] = "suspend-then-hibernate",
};

DEFINE_STRING_TABLE_LOOKUP(sleep_operation, SleepOperation);

static char* const* const sleep_default_state_table[_SLEEP_OPERATION_CONFIG_MAX] = {
        [SLEEP_SUSPEND]      = STRV_MAKE("mem", "standby", "freeze"),
        [SLEEP_HIBERNATE]    = STRV_MAKE("disk"),
        [SLEEP_HYBRID_SLEEP] = STRV_MAKE("disk"),
};

static char* const* const sleep_default_mode_table[_SLEEP_OPERATION_CONFIG_MAX] = {
        /* Not used by SLEEP_SUSPEND */
        [SLEEP_HIBERNATE]    = STRV_MAKE("platform", "shutdown"),
        [SLEEP_HYBRID_SLEEP] = STRV_MAKE("suspend"),
};

SleepConfig* sleep_config_free(SleepConfig *sc) {
        if (!sc)
                return NULL;

        for (SleepOperation i = 0; i < _SLEEP_OPERATION_CONFIG_MAX; i++) {
                strv_free(sc->states[i]);
                strv_free(sc->modes[i]);
        }

        strv_free(sc->mem_modes);

        return mfree(sc);
}

static int config_parse_sleep_mode(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = ASSERT_PTR(data);
        _cleanup_strv_free_ char **modes = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                modes = strv_new(NULL);
                if (!modes)
                        return log_oom();
        } else {
                r = strv_split_full(&modes, rvalue, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return log_oom();
        }

        return strv_free_and_replace(*sv, modes);
}

static void sleep_config_validate_state_and_mode(SleepConfig *sc) {
        assert(sc);

        /* So we should really not allow setting SuspendState= to 'disk', which means hibernation. We have
         * SLEEP_HIBERNATE for proper hibernation support, which includes checks for resume support (through
         * EFI variable or resume= kernel command line option). It's simply not sensible to call the suspend
         * operation but eventually do an unsafe hibernation. */
        if (strv_contains(sc->states[SLEEP_SUSPEND], "disk")) {
                strv_remove(sc->states[SLEEP_SUSPEND], "disk");
                log_warning("Sleep state 'disk' is not supported by operation %s, ignoring.",
                            sleep_operation_to_string(SLEEP_SUSPEND));
        }
        assert(!sc->modes[SLEEP_SUSPEND]);

        /* People should use hybrid-sleep instead of setting HibernateMode=suspend. Warn about it but don't
         * drop it in this case. */
        if (strv_contains(sc->modes[SLEEP_HIBERNATE], "suspend"))
                log_warning("Sleep mode 'suspend' should not be used by operation %s. Please use %s instead.",
                            sleep_operation_to_string(SLEEP_HIBERNATE), sleep_operation_to_string(SLEEP_HYBRID_SLEEP));
}

int parse_sleep_config(SleepConfig **ret) {
        _cleanup_(sleep_config_freep) SleepConfig *sc = NULL;
        int allow_suspend = -1, allow_hibernate = -1, allow_s2h = -1, allow_hybrid_sleep = -1;

        assert(ret);

        sc = new(SleepConfig, 1);
        if (!sc)
                return log_oom();

        *sc = (SleepConfig) {
                .hibernate_delay_usec = USEC_INFINITY,
        };

        const ConfigTableItem items[] = {
                { "Sleep", "AllowSuspend",              config_parse_tristate,    0,               &allow_suspend               },
                { "Sleep", "AllowHibernation",          config_parse_tristate,    0,               &allow_hibernate             },
                { "Sleep", "AllowSuspendThenHibernate", config_parse_tristate,    0,               &allow_s2h                   },
                { "Sleep", "AllowHybridSleep",          config_parse_tristate,    0,               &allow_hybrid_sleep          },

                { "Sleep", "SuspendState",              config_parse_strv,        0,               sc->states + SLEEP_SUSPEND   },
                { "Sleep", "SuspendMode",               config_parse_warn_compat, DISABLED_LEGACY, NULL                         },

                { "Sleep", "HibernateState",            config_parse_warn_compat, DISABLED_LEGACY, NULL                         },
                { "Sleep", "HibernateMode",             config_parse_sleep_mode,  0,               sc->modes + SLEEP_HIBERNATE  },

                { "Sleep", "HybridSleepState",          config_parse_warn_compat, DISABLED_LEGACY, NULL                         },
                { "Sleep", "HybridSleepMode",           config_parse_warn_compat, DISABLED_LEGACY, NULL                         },

                { "Sleep", "MemorySleepMode",           config_parse_sleep_mode,  0,               &sc->mem_modes               },

                { "Sleep", "HibernateDelaySec",         config_parse_sec,         0,               &sc->hibernate_delay_usec    },
                { "Sleep", "SuspendEstimationSec",      config_parse_sec,         0,               &sc->suspend_estimation_usec },
                {}
        };

        (void) config_parse_standard_file_with_dropins(
                        "systemd/sleep.conf",
                        "Sleep\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);

        /* use default values unless set */
        sc->allow[SLEEP_SUSPEND] = allow_suspend != 0;
        sc->allow[SLEEP_HIBERNATE] = allow_hibernate != 0;
        sc->allow[SLEEP_HYBRID_SLEEP] = allow_hybrid_sleep >= 0 ? allow_hybrid_sleep
                : (allow_suspend != 0 && allow_hibernate != 0);
        sc->allow[SLEEP_SUSPEND_THEN_HIBERNATE] = allow_s2h >= 0 ? allow_s2h
                : (allow_suspend != 0 && allow_hibernate != 0);

        for (SleepOperation i = 0; i < _SLEEP_OPERATION_CONFIG_MAX; i++) {
                if (!sc->states[i] && sleep_default_state_table[i]) {
                        sc->states[i] = strv_copy(sleep_default_state_table[i]);
                        if (!sc->states[i])
                                return log_oom();
                }

                if (!sc->modes[i] && sleep_default_mode_table[i]) {
                        sc->modes[i] = strv_copy(sleep_default_mode_table[i]);
                        if (!sc->modes[i])
                                return log_oom();
                }
        }

        if (sc->suspend_estimation_usec == 0)
                sc->suspend_estimation_usec = DEFAULT_SUSPEND_ESTIMATION_USEC;

        sleep_config_validate_state_and_mode(sc);

        *ret = TAKE_PTR(sc);
        return 0;
}
