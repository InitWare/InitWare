/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include "macro.h"

/* An embeddable structure carrying a reference to a process. Supposed to be used when tracking processes continuously. */
typedef struct PidRef {
        pid_t pid; /* always valid */
        int fd;    /* only valid if pidfd are available in the kernel, and we manage to get an fd */
} PidRef;

#define PIDREF_NULL (const PidRef) { .fd = -EBADF }

/* Turns a pid_t into a PidRef structure on-the-fly *without* acquiring a pidfd for it. (As opposed to
 * pidref_set_pid() which does so *with* acquiring one, see below) */
#define PIDREF_MAKE_FROM_PID(x) (PidRef) { .pid = (x), .fd = -EBADF }

static inline bool pidref_is_set(const PidRef *pidref) {
        return pidref && pidref->pid > 0;
}

bool pidref_equal(const PidRef *a, const PidRef *b);

int pidref_set_pid(PidRef *pidref, pid_t pid);
int pidref_set_pidfd(PidRef *pidref, int fd);

bool pidref_is_self(const PidRef *pidref);

void pidref_done(PidRef *pidref);
PidRef *pidref_free(PidRef *pidref);
DEFINE_TRIVIAL_CLEANUP_FUNC(PidRef*, pidref_free);

int pidref_verify(const PidRef *pidref);
