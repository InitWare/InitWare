/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>

typedef enum CatFlags {
        CAT_CONFIG_OFF          = 0,
        CAT_CONFIG_ON           = 1 << 0,
        CAT_FORMAT_HAS_SECTIONS = 1 << 1,  /* Sections are meaningful for this file format */
        CAT_TLDR                = 1 << 2,  /* Only print comments and relevant section headers */
} CatFlags;

bool urlify_enabled(void);

int terminal_urlify(const char *url, const char *text, char **ret);
int terminal_urlify_man(const char *page, const char *section, char **ret);
