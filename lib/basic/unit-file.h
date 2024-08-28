/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "path-lookup.h"
#include "time-util.h"
#include "unit-name.h"

typedef enum UnitFileState UnitFileState;

enum UnitFileState {
        UNIT_FILE_ENABLED,
        UNIT_FILE_ENABLED_RUNTIME,
        UNIT_FILE_LINKED,
        UNIT_FILE_LINKED_RUNTIME,
        UNIT_FILE_ALIAS,
        UNIT_FILE_MASKED,
        UNIT_FILE_MASKED_RUNTIME,
        UNIT_FILE_STATIC,
        UNIT_FILE_DISABLED,
        UNIT_FILE_INDIRECT,
        UNIT_FILE_GENERATED,
        UNIT_FILE_TRANSIENT,
        UNIT_FILE_BAD,
        _UNIT_FILE_STATE_MAX,
        _UNIT_FILE_STATE_INVALID = -EINVAL,
};

bool unit_type_may_alias(UnitType type) _const_;
bool unit_type_may_template(UnitType type) _const_;

int unit_symlink_name_compatible(const char *symlink, const char *target, bool instance_propagation);
int unit_validate_alias_symlink_or_warn(int log_level, const char *filename, const char *target);

int unit_file_resolve_symlink(
                const char *root_dir,
                char **search_path,
                const char *dir,
                int dirfd,
                const char *filename,
                bool resolve_destination_target,
                char **ret_destination);
