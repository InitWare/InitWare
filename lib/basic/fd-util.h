/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"
#include "stdio-util.h"

/* Make sure we can distuingish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd) + 1)
#define PTR_TO_FD(p) (PTR_TO_INT(p) - 1)

/* Useful helpers for initializing pipe(), socketpair() or stdio fd arrays */
#define EBADF_PAIR { -EBADF, -EBADF }
#define EBADF_TRIPLET { -EBADF, -EBADF, -EBADF }

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

int fd_reopen(int fd, int flags);
int fd_reopen_condition(int fd, int flags, int mask, int *ret_new_fd);

int path_is_root_at(int dir_fd, const char *path);
static inline int path_is_root(const char *path) {
        return path_is_root_at(AT_FDCWD, path);
}
static inline int dir_fd_is_root(int dir_fd) {
        return path_is_root_at(dir_fd, NULL);
}
static inline int dir_fd_is_root_or_cwd(int dir_fd) {
        return dir_fd == AT_FDCWD ? true : path_is_root_at(dir_fd, NULL);
}

int fds_are_same_mount(int fd1, int fd2);

/* The maximum length a buffer for a /proc/self/fd/<fd> path needs */
#define PROC_FD_PATH_MAX \
        (STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int))

static inline char *format_proc_fd_path(char buf[static PROC_FD_PATH_MAX], int fd) {
        assert(buf);
        assert(fd >= 0);
        assert_se(snprintf_ok(buf, PROC_FD_PATH_MAX, "/proc/self/fd/%i", fd));
        return buf;
}

#define FORMAT_PROC_FD_PATH(fd) \
        format_proc_fd_path((char[PROC_FD_PATH_MAX]) {}, (fd))
