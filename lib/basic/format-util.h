/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <inttypes.h>

#include "stdio-util.h"

assert_cc(sizeof(pid_t) == sizeof(int32_t));
#define PID_PRI PRIi32
#define PID_FMT "%" PID_PRI

assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define UID_FMT "%" PRIu32

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define GID_FMT "%" PRIu32

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_UID(uid) \
        snprintf_ok((char[DECIMAL_STR_MAX(uid_t)]){}, DECIMAL_STR_MAX(uid_t), UID_FMT, uid)
#define FORMAT_GID(gid) \
        snprintf_ok((char[DECIMAL_STR_MAX(gid_t)]){}, DECIMAL_STR_MAX(gid_t), GID_FMT, gid)

typedef enum {
        FORMAT_BYTES_USE_IEC     = 1 << 0,
        FORMAT_BYTES_BELOW_POINT = 1 << 1,
        FORMAT_BYTES_TRAILING_B  = 1 << 2,
} FormatBytesFlag;

#define FORMAT_BYTES_MAX 16U

char *format_bytes_full(char *buf, size_t l, uint64_t t, FormatBytesFlag flag) _warn_unused_result_;

_warn_unused_result_
static inline char *format_bytes(char *buf, size_t l, uint64_t t) {
        return format_bytes_full(buf, l, t, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
}

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_BYTES(t) format_bytes((char[FORMAT_BYTES_MAX]){}, FORMAT_BYTES_MAX, t)
