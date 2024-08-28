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

#include "string-util.h"

typedef int (*SpecifierCallback)(char specifier, const void *data, const char *root, const void *userdata, char **ret);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        const void *data;
} Specifier;

int specifier_printf(const char *text, size_t max_length, const Specifier table[], const char *root, const void *userdata, char **ret);

int specifier_string(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_real_path(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_real_directory(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_id128(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_uuid(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_uint64(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_machine_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_boot_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_short_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_pretty_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_kernel_release(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_architecture(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_version_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_build_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_variant_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_version(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_group_name(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_group_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_name(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_home(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_shell(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_var_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);

#define COMMON_SYSTEM_SPECIFIERS                   \
        { 'a', specifier_architecture,     NULL }, \
        { 'A', specifier_os_image_version, NULL }, \
        { 'b', specifier_boot_id,          NULL }, \
        { 'B', specifier_os_build_id,      NULL }, \
        { 'H', specifier_hostname,         NULL }, \
        { 'l', specifier_short_hostname,   NULL }, \
        { 'q', specifier_pretty_hostname,  NULL }, \
        { 'm', specifier_machine_id,       NULL }, \
        { 'M', specifier_os_image_id,      NULL }, \
        { 'o', specifier_os_id,            NULL }, \
        { 'v', specifier_kernel_release,   NULL }, \
        { 'w', specifier_os_version_id,    NULL }, \
        { 'W', specifier_os_variant_id,    NULL }

#define COMMON_CREDS_SPECIFIERS(scope)                           \
        { 'g', specifier_group_name,       INT_TO_PTR(scope) },  \
        { 'G', specifier_group_id,         INT_TO_PTR(scope) },  \
        { 'u', specifier_user_name,        INT_TO_PTR(scope) },  \
        { 'U', specifier_user_id,          INT_TO_PTR(scope) }

#define COMMON_TMP_SPECIFIERS                      \
        { 'T', specifier_tmp_dir,          NULL }, \
        { 'V', specifier_var_tmp_dir,      NULL }

static inline char* specifier_escape(const char *string) {
        return strreplace(string, "%", "%%");
}

int specifier_escape_strv(char **l, char ***ret);

/* A generic specifier table consisting of COMMON_SYSTEM_SPECIFIERS and COMMON_TMP_SPECIFIERS */
extern const Specifier system_and_tmp_specifier_table[];
