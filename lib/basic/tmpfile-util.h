/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>

int fopen_temporary_at(int dir_fd, const char *path, FILE **ret_file, char **ret_path);
static inline int fopen_temporary(const char *path, FILE **ret_file, char **ret_path) {
        return fopen_temporary_at(AT_FDCWD, path, ret_file, ret_path);
}

int mkostemp_safe(char *pattern);

int open_tmpfile_unlinkable(const char *directory, int flags);

int tempfn_xxxxxx(const char *p, const char *extra, char **ret);
int tempfn_random(const char *p, const char *extra, char **ret);
int tempfn_random_child(const char *p, const char *extra, char **ret);

int mkdtemp_malloc(const char *template, char **ret);
