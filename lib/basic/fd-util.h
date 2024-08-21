/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"

/* Make sure we can distuingish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd) + 1)
#define PTR_TO_FD(p) (PTR_TO_INT(p) - 1)

int fclose_nointr(FILE *f);
FILE* safe_fclose(FILE *f);

int fd_get_path(int fd, char **ret);

int fd_move_above_stdio(int fd);

/* Like TAKE_PTR() but for file descriptors, resetting them to -EBADF */
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

/* Like free_and_replace(), but for file descriptors */
#define close_and_replace(a, b)                 \
        ({                                      \
                int *_fdp_ = &(a);              \
                safe_close(*_fdp_);             \
                *_fdp_ = TAKE_FD(b);            \
                0;                              \
        })
