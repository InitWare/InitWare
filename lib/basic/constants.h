/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

/* Return a nulstr for a standard cascade of configuration paths, suitable to pass to
 * conf_files_list_nulstr() to implement drop-in directories for extending configuration files. */
#define CONF_PATHS_NULSTR(n)                    \
        "/etc/" n "\0"                          \
        "/run/" n "\0"                          \
        "/usr/local/lib/" n "\0"                \
        "/usr/lib/" n "\0"

#define CONF_PATHS(n)                           \
        "/etc/" n,                              \
        "/run/" n,                              \
        "/usr/local/lib/" n,                    \
        "/usr/lib/" n

#define CONF_PATHS_STRV(n)                      \
        STRV_MAKE(CONF_PATHS(n))

// HACK: Systemd uses configure time magic for this
#define DEFAULT_USER_TIMEOUT_SEC 60
#define DEFAULT_USER_TIMEOUT_USEC (DEFAULT_USER_TIMEOUT_SEC*USEC_PER_SEC)
