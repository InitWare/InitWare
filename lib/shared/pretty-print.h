/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

typedef enum CatFlags {
        CAT_CONFIG_OFF          = 0,
        CAT_CONFIG_ON           = 1 << 0,
        CAT_FORMAT_HAS_SECTIONS = 1 << 1,  /* Sections are meaningful for this file format */
        CAT_TLDR                = 1 << 2,  /* Only print comments and relevant section headers */
} CatFlags;
