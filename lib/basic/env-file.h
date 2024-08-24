/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>

#include "macro.h"

int parse_env_file_fdv(int fd, const char *fname, va_list ap);
