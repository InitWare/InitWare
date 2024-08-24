/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "format-table.h"

int table_add_many_internal(Table *t, TableDataType first_type, ...) {
        TableCell *last_cell = NULL;
        va_list ap;
        int r;

        assert(t);
        assert(first_type >= 0);
        assert(first_type < _TABLE_DATA_TYPE_MAX);

        va_start(ap, first_type);

        for (TableDataType type = first_type;; type = va_arg(ap, TableDataType)) {
                const void *data;
                union {
                        uint64_t size;
                        usec_t usec;
                        int int_val;
                        int8_t int8;
                        int16_t int16;
                        int32_t int32;
                        int64_t int64;
                        unsigned uint_val;
                        uint8_t uint8;
                        uint16_t uint16;
                        uint32_t uint32;
                        uint64_t uint64;
                        int percent;
                        int ifindex;
                        bool b;
                        union in_addr_union address;
                        sd_id128_t id128;
                        uid_t uid;
                        gid_t gid;
                        pid_t pid;
                        mode_t mode;
                        dev_t devnum;
                } buffer;

                switch (type) {

                case TABLE_EMPTY:
                        data = NULL;
                        break;

                case TABLE_STRING:
                case TABLE_PATH:
                case TABLE_PATH_BASENAME:
                case TABLE_FIELD:
                case TABLE_HEADER:
                        data = va_arg(ap, const char *);
                        break;

                case TABLE_STRV:
                case TABLE_STRV_WRAPPED:
                        data = va_arg(ap, char * const *);
                        break;

                case TABLE_BOOLEAN_CHECKMARK:
                case TABLE_BOOLEAN:
                        buffer.b = va_arg(ap, int);
                        data = &buffer.b;
                        break;

                case TABLE_TIMESTAMP:
                case TABLE_TIMESTAMP_UTC:
                case TABLE_TIMESTAMP_RELATIVE:
                case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
                case TABLE_TIMESTAMP_LEFT:
                case TABLE_TIMESTAMP_DATE:
                case TABLE_TIMESPAN:
                case TABLE_TIMESPAN_MSEC:
                case TABLE_TIMESPAN_DAY:
                        buffer.usec = va_arg(ap, usec_t);
                        data = &buffer.usec;
                        break;

                case TABLE_SIZE:
                case TABLE_BPS:
                        buffer.size = va_arg(ap, uint64_t);
                        data = &buffer.size;
                        break;

                case TABLE_INT:
                case TABLE_SIGNAL:
                        buffer.int_val = va_arg(ap, int);
                        data = &buffer.int_val;
                        break;

                case TABLE_INT8: {
                        int x = va_arg(ap, int);
                        assert(x >= INT8_MIN && x <= INT8_MAX);

                        buffer.int8 = x;
                        data = &buffer.int8;
                        break;
                }

                case TABLE_INT16: {
                        int x = va_arg(ap, int);
                        assert(x >= INT16_MIN && x <= INT16_MAX);

                        buffer.int16 = x;
                        data = &buffer.int16;
                        break;
                }

                case TABLE_INT32:
                        buffer.int32 = va_arg(ap, int32_t);
                        data = &buffer.int32;
                        break;

                case TABLE_INT64:
                        buffer.int64 = va_arg(ap, int64_t);
                        data = &buffer.int64;
                        break;

                case TABLE_UINT:
                        buffer.uint_val = va_arg(ap, unsigned);
                        data = &buffer.uint_val;
                        break;

                case TABLE_UINT8: {
                        unsigned x = va_arg(ap, unsigned);
                        assert(x <= UINT8_MAX);

                        buffer.uint8 = x;
                        data = &buffer.uint8;
                        break;
                }

                case TABLE_UINT16: {
                        unsigned x = va_arg(ap, unsigned);
                        assert(x <= UINT16_MAX);

                        buffer.uint16 = x;
                        data = &buffer.uint16;
                        break;
                }

                case TABLE_UINT32:
                case TABLE_UINT32_HEX:
                        buffer.uint32 = va_arg(ap, uint32_t);
                        data = &buffer.uint32;
                        break;

                case TABLE_UINT64:
                case TABLE_UINT64_HEX:
                        buffer.uint64 = va_arg(ap, uint64_t);
                        data = &buffer.uint64;
                        break;

                case TABLE_PERCENT:
                        buffer.percent = va_arg(ap, int);
                        data = &buffer.percent;
                        break;

                case TABLE_IFINDEX:
                        buffer.ifindex = va_arg(ap, int);
                        data = &buffer.ifindex;
                        break;

                case TABLE_IN_ADDR:
                        buffer.address = *va_arg(ap, union in_addr_union *);
                        data = &buffer.address.in;
                        break;

                case TABLE_IN6_ADDR:
                        buffer.address = *va_arg(ap, union in_addr_union *);
                        data = &buffer.address.in6;
                        break;

                case TABLE_UUID:
                case TABLE_ID128:
                        buffer.id128 = va_arg(ap, sd_id128_t);
                        data = &buffer.id128;
                        break;

                case TABLE_UID:
                        buffer.uid = va_arg(ap, uid_t);
                        data = &buffer.uid;
                        break;

                case TABLE_GID:
                        buffer.gid = va_arg(ap, gid_t);
                        data = &buffer.gid;
                        break;

                case TABLE_PID:
                        buffer.pid = va_arg(ap, pid_t);
                        data = &buffer.pid;
                        break;

                case TABLE_MODE:
                case TABLE_MODE_INODE_TYPE:
                        buffer.mode = va_arg(ap, mode_t);
                        data = &buffer.mode;
                        break;

                case TABLE_DEVNUM:
                        buffer.devnum = va_arg(ap, dev_t);
                        data = &buffer.devnum;
                        break;

                case TABLE_SET_MINIMUM_WIDTH: {
                        size_t w = va_arg(ap, size_t);

                        r = table_set_minimum_width(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_MAXIMUM_WIDTH: {
                        size_t w = va_arg(ap, size_t);
                        r = table_set_maximum_width(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_WEIGHT: {
                        unsigned w = va_arg(ap, unsigned);
                        r = table_set_weight(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_ALIGN_PERCENT: {
                        unsigned p = va_arg(ap, unsigned);
                        r = table_set_align_percent(t, last_cell, p);
                        goto check;
                }

                case TABLE_SET_ELLIPSIZE_PERCENT: {
                        unsigned p = va_arg(ap, unsigned);
                        r = table_set_ellipsize_percent(t, last_cell, p);
                        goto check;
                }

                case TABLE_SET_COLOR: {
                        const char *c = va_arg(ap, const char*);
                        r = table_set_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_RGAP_COLOR: {
                        const char *c = va_arg(ap, const char*);
                        r = table_set_rgap_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_BOTH_COLORS: {
                        const char *c = va_arg(ap, const char*);

                        r = table_set_color(t, last_cell, c);
                        if (r < 0) {
                                va_end(ap);
                                return r;
                        }

                        r = table_set_rgap_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_UNDERLINE: {
                        int u = va_arg(ap, int);
                        r = table_set_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_RGAP_UNDERLINE: {
                        int u = va_arg(ap, int);
                        r = table_set_rgap_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_BOTH_UNDERLINES: {
                        int u = va_arg(ap, int);

                        r = table_set_underline(t, last_cell, u);
                        if (r < 0) {
                                va_end(ap);
                                return r;
                        }

                        r = table_set_rgap_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_URL: {
                        const char *u = va_arg(ap, const char*);
                        r = table_set_url(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_UPPERCASE: {
                        int u = va_arg(ap, int);
                        r = table_set_uppercase(t, last_cell, u);
                        goto check;
                }

                case _TABLE_DATA_TYPE_MAX:
                        /* Used as end marker */
                        va_end(ap);
                        return 0;

                default:
                        assert_not_reached();
                }

                r = table_add_cell(t, &last_cell, type, data);
        check:
                if (r < 0) {
                        va_end(ap);
                        return r;
                }
        }
}
