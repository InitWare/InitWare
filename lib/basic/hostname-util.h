/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

typedef enum GetHostnameFlags {
        GET_HOSTNAME_ALLOW_LOCALHOST  = 1 << 0, /* accepts "localhost" or friends. */
        GET_HOSTNAME_FALLBACK_DEFAULT = 1 << 1, /* use default hostname if no hostname is set. */
        GET_HOSTNAME_SHORT            = 1 << 2, /* kills the FQDN part if present. */
} GetHostnameFlags;

int gethostname_full(GetHostnameFlags flags, char **ret);
static inline int gethostname_strict(char **ret) {
        return gethostname_full(0, ret);
}

static inline char* gethostname_malloc(void) {
        char *s;

        if (gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &s) < 0)
                return NULL;

        return s;
}

static inline char* gethostname_short_malloc(void) {
        char *s;

        if (gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT | GET_HOSTNAME_SHORT, &s) < 0)
                return NULL;

        return s;
}

int get_pretty_hostname(char **ret);
