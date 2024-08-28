/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

int parse_boolean(const char *v) _pure_;
int parse_tristate_full(const char *v, const char *third, int *ret);
static inline int parse_tristate(const char *v, int *ret) {
        return parse_tristate_full(v, NULL, ret);
}
int parse_pid(const char *s, pid_t* ret_pid);
int parse_ifindex(const char *s);
