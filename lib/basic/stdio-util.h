/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2010-2021 the systemd authors */

#ifndef STDIO_UTIL_H_
#define STDIO_UTIL_H_

#include "util.h"

#define snprintf_ok(buf, len, fmt, ...)                                \
        ({                                                             \
                char *_buf = (buf);                                    \
                size_t _len = (len);                                   \
                int _snpf = snprintf(_buf, _len, (fmt), __VA_ARGS__);  \
                _snpf >= 0 && (size_t) _snpf < _len ? _buf : NULL;     \
        })

#endif /* STDIO_UTIL_H_ */
