/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll);

int loop_write_full(int fd, const void *buf, size_t nbytes, usec_t timeout);
static inline int loop_write(int fd, const void *buf, size_t nbytes) {
        return loop_write_full(fd, buf, nbytes, 0);
}
