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

#include "macro.h"
#include "runtime-scope.h"

typedef enum UnitFileScope UnitFileScope;

typedef enum LookupPathsFlags {
        LOOKUP_PATHS_EXCLUDE_GENERATED   = 1 << 0,
        LOOKUP_PATHS_TEMPORARY_GENERATED = 1 << 1,
        LOOKUP_PATHS_SPLIT_USR           = 1 << 2, /* Legacy, use ONLY for image payloads which might be old */
} LookupPathsFlags;

// typedef struct LookupPaths {
// 	char **unit_path;
// #ifdef HAVE_SYSV_COMPAT
// 	char **sysvinit_path;
// 	char **sysvrcnd_path;
// #endif
// } LookupPaths;

typedef struct LookupPaths {
        /* Where we look for unit files. This includes the individual special paths below, but also any vendor
         * supplied, static unit file paths. */
        char **search_path;

        /* Where we shall create or remove our installation symlinks, aka "configuration", and where the user/admin
         * shall place their own unit files. */
        char *persistent_config;
        char *runtime_config;

        /* Where units from a portable service image shall be placed. */
        char *persistent_attached;
        char *runtime_attached;

        /* Where to place generated unit files (i.e. those a "generator" tool generated). Note the special semantics of
         * this directory: the generators are flushed each time a "systemctl daemon-reload" is issued. The user should
         * not alter these directories directly. */
        char *generator;
        char *generator_early;
        char *generator_late;

        /* Where to place transient unit files (i.e. those created dynamically via the bus API). Note the special
         * semantics of this directory: all units created transiently have their unit files removed as the transient
         * unit is unloaded. The user should not alter this directory directly. */
        char *transient;

        /* Where the snippets created by "systemctl set-property" are placed. Note that for transient units, the
         * snippets are placed in the transient directory though (see above). The user should not alter this directory
         * directly. */
        char *persistent_control;
        char *runtime_control;

        /* The root directory prepended to all items above, or NULL */
        char *root_dir;

        /* A temporary directory when running in test mode, to be nuked */
        char *temporary_dir;
        char **unit_path;
#ifdef HAVE_SYSV_COMPAT
				char **sysvinit_path;
				char **sysvrcnd_path;
#endif
} LookupPaths;

typedef enum SystemdRunningAs {
	SYSTEMD_SYSTEM,
	SYSTEMD_USER,
	_SYSTEMD_RUNNING_AS_MAX,
	_SYSTEMD_RUNNING_AS_INVALID = -1
} SystemdRunningAs;

int user_config_home(char **config_home);
int user_runtime_dir(char **runtime_dir);

char **generator_paths(SystemdRunningAs running_as);

int lookup_paths_init(LookupPaths *lp, RuntimeScope scope, LookupPathsFlags flags, const char *root_dir);
// int lookup_paths_init(LookupPaths *p, SystemdRunningAs running_as,
// 	bool personal, const char *root_dir, const char *generator,
// 	const char *generator_early, const char *generator_late);
void lookup_paths_free(LookupPaths *p);
int lookup_paths_init_from_scope(LookupPaths *paths, UnitFileScope scope,
	const char *root_dir);

void lookup_paths_done(LookupPaths *p);

#define _cleanup_lookup_paths_free_ _cleanup_(lookup_paths_free)
