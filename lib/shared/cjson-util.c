/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */

/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include "cjson-util.h"

char *xcJSON_steal_valuestring(cJSON *obj) {
        char *result = obj->valuestring;
        obj->valuestring = NULL;
        return result;
}