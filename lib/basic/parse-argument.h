/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include "json.h"

int parse_boolean_argument(const char *optname, const char *s, bool *ret);
int parse_json_argument(const char *s, JsonFormatFlags *ret);
