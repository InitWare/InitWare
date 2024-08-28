/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdio.h>

typedef struct MemStream {
        FILE *f;
        char *buf;
        size_t sz;
} MemStream;

void memstream_done(MemStream *m);
FILE* memstream_init(MemStream *m);
int memstream_finalize(MemStream *m, char **ret_buf, size_t *ret_size);
