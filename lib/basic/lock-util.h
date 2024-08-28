/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>

typedef struct LockFile {
        int dir_fd;
        char *path;
        int fd;
        int operation;
} LockFile;

int make_lock_file_at(int dir_fd, const char *p, int operation, LockFile *ret);
static inline int make_lock_file(const char *p, int operation, LockFile *ret) {
        return make_lock_file_at(AT_FDCWD, p, operation, ret);
}
int make_lock_file_for(const char *p, int operation, LockFile *ret);
void release_lock_file(LockFile *f);

typedef enum LockType {
        LOCK_NONE, /* Don't lock the file descriptor. Useful if you need to conditionally lock a file. */
        LOCK_BSD,
        LOCK_POSIX,
        LOCK_UNPOSIX,
} LockType;
