/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>

int mkdtemp_malloc(const char *template, char **ret);
