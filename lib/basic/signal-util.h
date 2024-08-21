/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <signal.h>

#include "macro.h"
// #include "util.h"

static inline bool SIGNAL_VALID(int signo) {
        return signo > 0 && signo < _NSIG;
}

int signal_is_blocked(int sig);
