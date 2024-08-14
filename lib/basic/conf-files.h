#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
  Copyright 2010-2012 Kay Sievers

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

#include <stdbool.h>

#include "macro.h"

enum {
        CONF_FILES_EXECUTABLE    = 1 << 0,
        CONF_FILES_REGULAR       = 1 << 1,
        CONF_FILES_DIRECTORY     = 1 << 2,
        CONF_FILES_BASENAME      = 1 << 3,
        CONF_FILES_FILTER_MASKED = 1 << 4,
};

int conf_files_list(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dir);
int conf_files_list_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dir);
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, unsigned flags, const char* const* dirs);
int conf_files_list_strv_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char * const *dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dirs);
int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dirs);
int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path);
int conf_files_list_dropins(
                char ***ret,
                const char *dropin_dirname,
                const char *root,
                const char * const *dirs);
