/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll);
