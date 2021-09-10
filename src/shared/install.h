/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include "hashmap.h"
#include "unit-name.h"
#include "path-lookup.h"
#include "strv.h"

typedef enum UnitFileScope {
        UNIT_FILE_SYSTEM,
        UNIT_FILE_GLOBAL,
        UNIT_FILE_USER,
        _UNIT_FILE_SCOPE_MAX,
        _UNIT_FILE_SCOPE_INVALID = -1
} UnitFileScope;

typedef enum UnitFileState {
        UNIT_FILE_ENABLED,
        UNIT_FILE_ENABLED_RUNTIME,
        UNIT_FILE_LINKED,
        UNIT_FILE_LINKED_RUNTIME,
        UNIT_FILE_MASKED,
        UNIT_FILE_MASKED_RUNTIME,
        UNIT_FILE_STATIC,
        UNIT_FILE_DISABLED,
        UNIT_FILE_INDIRECT,
        UNIT_FILE_BAD,
        _UNIT_FILE_STATE_MAX,
        _UNIT_FILE_STATE_INVALID = -1
} UnitFileState;

typedef enum UnitFilePresetMode {
        UNIT_FILE_PRESET_FULL,
        UNIT_FILE_PRESET_ENABLE_ONLY,
        UNIT_FILE_PRESET_DISABLE_ONLY,
        _UNIT_FILE_PRESET_MAX,
        _UNIT_FILE_PRESET_INVALID = -1
} UnitFilePresetMode;

typedef enum UnitFileChangeType {
        UNIT_FILE_SYMLINK,
        UNIT_FILE_UNLINK,
        UNIT_FILE_IS_MASKED,
        UNIT_FILE_IS_DANGLING,
        _UNIT_FILE_CHANGE_TYPE_MAX,
        _UNIT_FILE_CHANGE_TYPE_INVALID = -1
} UnitFileChangeType;

typedef enum UnitFileFlags {
        UNIT_FILE_RUNTIME = 1,
        UNIT_FILE_FORCE = 1 << 1,
        UNIT_FILE_DRY_RUN = 1 << 2
} UnitFileFlags;

static inline bool unit_file_change_is_modification(UnitFileChangeType type) {
        return IN_SET(type, UNIT_FILE_SYMLINK, UNIT_FILE_UNLINK);
}

typedef struct UnitFileChange {
        UnitFileChangeType type;
        char *path;
        char *source;
} UnitFileChange;

typedef struct UnitFileList {
        char *path;
        UnitFileState state;
} UnitFileList;

typedef enum UnitFileType {
        UNIT_FILE_TYPE_REGULAR,
        UNIT_FILE_TYPE_SYMLINK,
        UNIT_FILE_TYPE_MASKED,
       _UNIT_FILE_TYPE_MAX,
        _UNIT_FILE_TYPE_INVALID = -1,
} UnitFileType;

typedef struct {
        char *name;
        char *path;
        char *user;

        char **aliases;
        char **wanted_by;
        char **required_by;
        char **also;

        char *default_instance;

        UnitFileType type;

        char *symlink_target;
} InstallInfo;

static inline bool UNIT_FILE_INSTALL_INFO_HAS_RULES(InstallInfo *i) {
        assert(i);

        return !strv_isempty(i->aliases) ||
               !strv_isempty(i->wanted_by) ||
               !strv_isempty(i->required_by);
}

static inline bool UNIT_FILE_INSTALL_INFO_HAS_ALSO(InstallInfo *i) {
        assert(i);

        return !strv_isempty(i->also);
}

int unit_file_enable(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_disable(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_reenable(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_link(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_preset(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFilePresetMode mode, UnitFileChange **changes, unsigned *n_changes);
int unit_file_preset_all(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, UnitFilePresetMode mode, UnitFileChange **changes, unsigned *n_changes);
int unit_file_mask(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_unmask(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, unsigned *n_changes);
int unit_file_set_default(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, const char *file, UnitFileChange **changes, unsigned *n_changes);
int unit_file_get_default(UnitFileScope scope, const char *root_dir, char **name);
int unit_file_add_dependency(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, const char *target, UnitDependency dep, UnitFileChange **changes, unsigned *n_changes);

int unit_file_lookup_state(UnitFileScope scope, const char *root_dir,const LookupPaths *paths, const char *name, UnitFileState *ret);
int unit_file_get_state(UnitFileScope scope, const char *root_dir, const char *filename, UnitFileState *ret);

int unit_file_get_list(UnitFileScope scope, const char *root_dir, Hashmap *h);
Hashmap* unit_file_list_free(Hashmap *h);

int unit_file_changes_add(UnitFileChange **changes, unsigned *n_changes, UnitFileChangeType type, const char *path, const char *source);
void unit_file_changes_free(UnitFileChange *changes, unsigned n_changes);

int unit_file_query_preset(UnitFileScope scope, const char *root_dir, const char *name);

const char *unit_file_state_to_string(UnitFileState s) _const_;
UnitFileState unit_file_state_from_string(const char *s) _pure_;

const char *unit_file_change_type_to_string(UnitFileChangeType s) _const_;
UnitFileChangeType unit_file_change_type_from_string(const char *s) _pure_;

const char *unit_file_preset_mode_to_string(UnitFilePresetMode m) _const_;
UnitFilePresetMode unit_file_preset_mode_from_string(const char *s) _pure_;
