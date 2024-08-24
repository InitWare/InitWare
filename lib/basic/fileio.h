#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/
#include <stddef.h>
#include <stdio.h>

#include "macro.h"

int write_string_stream(FILE *f, const char *line);
int write_string_file(const char *fn, const char *line);
int write_string_file_no_create(const char *fn, const char *line);
int write_string_file_atomic(const char *fn, const char *line);

int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);

int load_env_file(FILE *f, const char *fname, const char *separator, char ***l);
int load_env_file_pairs(FILE *f, const char *fname, const char *separator,
	char ***l);

int fdopen_unlocked(int fd, const char *options, FILE **ret);
int take_fdopen_unlocked(int *fd, const char *options, FILE **ret);
FILE* take_fdopen(int *fd, const char *options);
FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc);

int write_env_file(const char *fname, char **l);

int executable_is_script(const char *path, char **interpreter);

int get_status_field(const char *filename, const char *pattern, char **field);

int fdopen_independent(int fd, const char *mode, FILE **ret);

static inline bool file_offset_beyond_memory_size(off_t x) {
        if (x < 0) /* off_t is signed, filter that out */
                return false;
        return (uint64_t) x > (uint64_t) SIZE_MAX;
}

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size);
int read_virtual_file_at(int dir_fd, const char *filename, size_t max_size, char **ret_contents, size_t *ret_size);
static inline int read_virtual_file(const char *filename, size_t max_size, char **ret_contents, size_t *ret_size) {
        return read_virtual_file_at(AT_FDCWD, filename, max_size, ret_contents, ret_size);
}
static inline int read_full_virtual_file(const char *filename, char **ret_contents, size_t *ret_size) {
        return read_virtual_file(filename, SIZE_MAX, ret_contents, ret_size);
}

int read_line(FILE *f, size_t limit, char **ret);
int read_stripped_line(FILE *f, size_t limit, char **ret);

int fopen_mode_to_flags(const char *mode);
