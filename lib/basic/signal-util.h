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

int pop_pending_signal_internal(int sig, ...);
#define pop_pending_signal(...) pop_pending_signal_internal(__VA_ARGS__, -1)
