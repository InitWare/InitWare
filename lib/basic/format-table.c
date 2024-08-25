/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "format-table.h"

#define DEFAULT_WEIGHT 100

typedef struct TableData {
        unsigned n_ref;
        TableDataType type;

        size_t minimum_width;       /* minimum width for the column */
        size_t maximum_width;       /* maximum width for the column */
        size_t formatted_for_width; /* the width we tried to format for */
        unsigned weight;            /* the horizontal weight for this column, in case the table is expanded/compressed */
        unsigned ellipsize_percent; /* 0 … 100, where to place the ellipsis when compression is needed */
        unsigned align_percent;     /* 0 … 100, where to pad with spaces when expanding is needed. 0: left-aligned, 100: right-aligned */

        bool uppercase:1;           /* Uppercase string on display */
        bool underline:1;
        bool rgap_underline:1;

        const char *color;          /* ANSI color string to use for this cell. When written to terminal should not move cursor. Will automatically be reset after the cell */
        const char *rgap_color;     /* The ANSI color to use for the gap right of this cell. Usually used to underline entire rows in a gapless fashion */
        char *url;                  /* A URL to use for a clickable hyperlink */
        char *formatted;            /* A cached textual representation of the cell data, before ellipsation/alignment */

        union {
                uint8_t data[0];    /* data is generic array */
                bool boolean;
                usec_t timestamp;
                usec_t timespan;
                uint64_t size;
                char string[0];
                char **strv;
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
                int percent;        /* we use 'int' as datatype for percent values in order to match the result of parse_percent() */
                int ifindex;
                union in_addr_union address;
                sd_id128_t id128;
                uid_t uid;
                gid_t gid;
                pid_t pid;
                mode_t mode;
                dev_t devnum;
                /* … add more here as we start supporting more cell data types … */
        };
} TableData;

static size_t TABLE_CELL_TO_INDEX(TableCell *cell) {
        size_t i;

        assert(cell);

        i = PTR_TO_SIZE(cell);
        assert(i > 0);

        return i-1;
}

static TableCell* TABLE_INDEX_TO_CELL(size_t index) {
        assert(index != SIZE_MAX);
        return SIZE_TO_PTR(index + 1);
}

struct Table {
        size_t n_columns;
        size_t n_cells;

        bool header;   /* Whether to show the header row? */
        bool vertical; /* Whether to field names are on the left rather than the first line */

        TableErsatz ersatz; /* What to show when we have an empty cell or an invalid value that cannot be rendered. */

        size_t width;  /* If == 0 format this as wide as necessary. If SIZE_MAX format this to console
                        * width or less wide, but not wider. Otherwise the width to format this table in. */
        size_t cell_height_max; /* Maximum number of lines per cell. (If there are more, ellipsis is shown. If SIZE_MAX then no limit is set, the default. == 0 is not allowed.) */

        TableData **data;

        size_t *display_map;  /* List of columns to show (by their index). It's fine if columns are listed multiple times or not at all */
        size_t n_display_map;

        size_t *sort_map;     /* The columns to order rows by, in order of preference. */
        size_t n_sort_map;

        char **json_fields;
        size_t n_json_fields;

        bool *reverse_map;
};

Table *table_new_raw(size_t n_columns) {
        _cleanup_(table_unrefp) Table *t = NULL;

        assert(n_columns > 0);

        t = new(Table, 1);
        if (!t)
                return NULL;

        *t = (struct Table) {
                .n_columns = n_columns,
                .header = true,
                .width = SIZE_MAX,
                .cell_height_max = SIZE_MAX,
                .ersatz = TABLE_ERSATZ_EMPTY,
        };

        return TAKE_PTR(t);
}

Table *table_new_internal(const char *first_header, ...) {
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t n_columns = 1;
        va_list ap;
        int r;

        assert(first_header);

        va_start(ap, first_header);
        for (;;) {
                if (!va_arg(ap, const char*))
                        break;

                n_columns++;
        }
        va_end(ap);

        t = table_new_raw(n_columns);
        if (!t)
                return NULL;

        va_start(ap, first_header);
        for (const char *h = first_header; h; h = va_arg(ap, const char*)) {
                TableCell *cell;

                r = table_add_cell(t, &cell, TABLE_HEADER, h);
                if (r < 0) {
                        va_end(ap);
                        return NULL;
                }
        }
        va_end(ap);

        assert(t->n_columns == t->n_cells);
        return TAKE_PTR(t);
}

Table *table_new_vertical(void) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell;

        t = table_new_raw(2);
        if (!t)
                return NULL;

        t->vertical = true;
        t->header = false;

        if (table_add_cell(t, &cell, TABLE_HEADER, "key") < 0)
                return NULL;

        if (table_set_align_percent(t, cell, 100) < 0)
                return NULL;

        if (table_add_cell(t, &cell, TABLE_HEADER, "value") < 0)
                return NULL;

        if (table_set_align_percent(t, cell, 0) < 0)
                return NULL;

        return TAKE_PTR(t);
}

static TableData *table_data_free(TableData *d) {
        assert(d);

        free(d->formatted);
        free(d->url);

        if (IN_SET(d->type, TABLE_STRV, TABLE_STRV_WRAPPED))
                strv_free(d->strv);

        return mfree(d);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(TableData, table_data, table_data_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(TableData*, table_data_unref);

Table *table_unref(Table *t) {
        if (!t)
                return NULL;

        for (size_t i = 0; i < t->n_cells; i++)
                table_data_unref(t->data[i]);

        free(t->data);
        free(t->display_map);
        free(t->sort_map);
        free(t->reverse_map);

        for (size_t i = 0; i < t->n_json_fields; i++)
                free(t->json_fields[i]);

        free(t->json_fields);

        return mfree(t);
}

static size_t table_data_size(TableDataType type, const void *data) {

        switch (type) {

        case TABLE_EMPTY:
                return 0;

        case TABLE_STRING:
        case TABLE_PATH:
        case TABLE_PATH_BASENAME:
        case TABLE_FIELD:
        case TABLE_HEADER:
                return strlen(data) + 1;

        case TABLE_STRV:
        case TABLE_STRV_WRAPPED:
                return sizeof(char **);

        case TABLE_BOOLEAN_CHECKMARK:
        case TABLE_BOOLEAN:
                return sizeof(bool);

        case TABLE_TIMESTAMP:
        case TABLE_TIMESTAMP_UTC:
        case TABLE_TIMESTAMP_RELATIVE:
        case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
        case TABLE_TIMESTAMP_LEFT:
        case TABLE_TIMESTAMP_DATE:
        case TABLE_TIMESPAN:
        case TABLE_TIMESPAN_MSEC:
        case TABLE_TIMESPAN_DAY:
                return sizeof(usec_t);

        case TABLE_SIZE:
        case TABLE_INT64:
        case TABLE_UINT64:
        case TABLE_UINT64_HEX:
        case TABLE_BPS:
                return sizeof(uint64_t);

        case TABLE_INT32:
        case TABLE_UINT32:
        case TABLE_UINT32_HEX:
                return sizeof(uint32_t);

        case TABLE_INT16:
        case TABLE_UINT16:
                return sizeof(uint16_t);

        case TABLE_INT8:
        case TABLE_UINT8:
                return sizeof(uint8_t);

        case TABLE_INT:
        case TABLE_UINT:
        case TABLE_PERCENT:
        case TABLE_IFINDEX:
        case TABLE_SIGNAL:
                return sizeof(int);

        case TABLE_IN_ADDR:
                return sizeof(struct in_addr);

        case TABLE_IN6_ADDR:
                return sizeof(struct in6_addr);

        case TABLE_UUID:
        case TABLE_ID128:
                return sizeof(sd_id128_t);

        case TABLE_UID:
                return sizeof(uid_t);
        case TABLE_GID:
                return sizeof(gid_t);
        case TABLE_PID:
                return sizeof(pid_t);

        case TABLE_MODE:
        case TABLE_MODE_INODE_TYPE:
                return sizeof(mode_t);

        case TABLE_DEVNUM:
                return sizeof(dev_t);

        default:
                assert_not_reached();
        }
}

static bool table_data_matches(
                TableData *d,
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent,
                bool uppercase) {

        size_t k, l;
        assert(d);

        if (d->type != type)
                return false;

        if (d->minimum_width != minimum_width)
                return false;

        if (d->maximum_width != maximum_width)
                return false;

        if (d->weight != weight)
                return false;

        if (d->align_percent != align_percent)
                return false;

        if (d->ellipsize_percent != ellipsize_percent)
                return false;

        if (d->uppercase != uppercase)
                return false;

        /* If a color/url is set, refuse to merge */
        if (d->color || d->rgap_color || d->underline || d->rgap_underline)
                return false;
        if (d->url)
                return false;

        k = table_data_size(type, data);
        l = table_data_size(d->type, d->data);
        if (k != l)
                return false;

        return memcmp_safe(data, d->data, l) == 0;
}

static TableData *table_data_new(
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent,
                bool uppercase) {

        _cleanup_free_ TableData *d = NULL;
        size_t data_size;

        data_size = table_data_size(type, data);

        d = malloc0(offsetof(TableData, data) + data_size);
        if (!d)
                return NULL;

        d->n_ref = 1;
        d->type = type;
        d->minimum_width = minimum_width;
        d->maximum_width = maximum_width;
        d->weight = weight;
        d->align_percent = align_percent;
        d->ellipsize_percent = ellipsize_percent;
        d->uppercase = uppercase;

        if (IN_SET(type, TABLE_STRV, TABLE_STRV_WRAPPED)) {
                d->strv = strv_copy(data);
                if (!d->strv)
                        return NULL;
        } else
                memcpy_safe(d->data, data, data_size);

        return TAKE_PTR(d);
}

int table_add_cell_full(
                Table *t,
                TableCell **ret_cell,
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent) {

        _cleanup_(table_data_unrefp) TableData *d = NULL;
        bool uppercase;
        TableData *p;

        assert(t);
        assert(type >= 0);
        assert(type < _TABLE_DATA_TYPE_MAX);

        /* Special rule: patch NULL data fields to the empty field */
        if (!data)
                type = TABLE_EMPTY;

        /* Determine the cell adjacent to the current one, but one row up */
        if (t->n_cells >= t->n_columns)
                assert_se(p = t->data[t->n_cells - t->n_columns]);
        else
                p = NULL;

        /* If formatting parameters are left unspecified, copy from the previous row */
        if (minimum_width == SIZE_MAX)
                minimum_width = p ? p->minimum_width : 1;

        if (weight == UINT_MAX)
                weight = p ? p->weight : DEFAULT_WEIGHT;

        if (align_percent == UINT_MAX)
                align_percent = p ? p->align_percent : 0;

        if (ellipsize_percent == UINT_MAX)
                ellipsize_percent = p ? p->ellipsize_percent : 100;

        assert(align_percent <= 100);
        assert(ellipsize_percent <= 100);

        uppercase = type == TABLE_HEADER;

        /* Small optimization: Pretty often adjacent cells in two subsequent lines have the same data and
         * formatting. Let's see if we can reuse the cell data and ref it once more. */

        if (p && table_data_matches(p, type, data, minimum_width, maximum_width, weight, align_percent, ellipsize_percent, uppercase))
                d = table_data_ref(p);
        else {
                d = table_data_new(type, data, minimum_width, maximum_width, weight, align_percent, ellipsize_percent, uppercase);
                if (!d)
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(t->data, MAX(t->n_cells + 1, t->n_columns)))
                return -ENOMEM;

        if (ret_cell)
                *ret_cell = TABLE_INDEX_TO_CELL(t->n_cells);

        t->data[t->n_cells++] = TAKE_PTR(d);

        return 0;
}

static int table_dedup_cell(Table *t, TableCell *cell) {
        _cleanup_free_ char *curl = NULL;
        TableData *nd, *od;
        size_t i;

        assert(t);

        /* Helper call that ensures the specified cell's data object has a ref count of 1, which we can use before
         * changing a cell's formatting without effecting every other cell's formatting that shares the same data */

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return -ENXIO;

        assert_se(od = t->data[i]);
        if (od->n_ref == 1)
                return 0;

        assert(od->n_ref > 1);

        if (od->url) {
                curl = strdup(od->url);
                if (!curl)
                        return -ENOMEM;
        }

        nd = table_data_new(
                        od->type,
                        od->data,
                        od->minimum_width,
                        od->maximum_width,
                        od->weight,
                        od->align_percent,
                        od->ellipsize_percent,
                        od->uppercase);
        if (!nd)
                return -ENOMEM;

        nd->color = od->color;
        nd->rgap_color = od->rgap_color;
        nd->underline = od->underline;
        nd->rgap_underline = od->rgap_underline;
        nd->url = TAKE_PTR(curl);

        table_data_unref(od);
        t->data[i] = nd;

        assert(nd->n_ref == 1);

        return 1;
}

static TableData *table_get_data(Table *t, TableCell *cell) {
        size_t i;

        assert(t);
        assert(cell);

        /* Get the data object of the specified cell, or NULL if it doesn't exist */

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return NULL;

        assert(t->data[i]);
        assert(t->data[i]->n_ref > 0);

        return t->data[i];
}

int table_set_minimum_width(Table *t, TableCell *cell, size_t minimum_width) {
        int r;

        assert(t);
        assert(cell);

        if (minimum_width == SIZE_MAX)
                minimum_width = 1;

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->minimum_width = minimum_width;
        return 0;
}

int table_set_maximum_width(Table *t, TableCell *cell, size_t maximum_width) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->maximum_width = maximum_width;
        return 0;
}

int table_set_weight(Table *t, TableCell *cell, unsigned weight) {
        int r;

        assert(t);
        assert(cell);

        if (weight == UINT_MAX)
                weight = DEFAULT_WEIGHT;

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->weight = weight;
        return 0;
}

int table_set_align_percent(Table *t, TableCell *cell, unsigned percent) {
        int r;

        assert(t);
        assert(cell);

        if (percent == UINT_MAX)
                percent = 0;

        assert(percent <= 100);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->align_percent = percent;
        return 0;
}

int table_set_ellipsize_percent(Table *t, TableCell *cell, unsigned percent) {
        int r;

        assert(t);
        assert(cell);

        if (percent == UINT_MAX)
                percent = 100;

        assert(percent <= 100);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->ellipsize_percent = percent;
        return 0;
}

int table_set_color(Table *t, TableCell *cell, const char *color) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->color = empty_to_null(color);
        return 0;
}

int table_set_rgap_color(Table *t, TableCell *cell, const char *color) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->rgap_color = empty_to_null(color);
        return 0;
}

int table_set_underline(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->underline == b)
                return 0;

        d->underline = b;
        return 1;
}

int table_set_rgap_underline(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->rgap_underline == b)
                return 0;

        d->rgap_underline = b;
        return 1;
}

int table_set_url(Table *t, TableCell *cell, const char *url) {
        _cleanup_free_ char *copy = NULL;
        int r;

        assert(t);
        assert(cell);

        if (url) {
                copy = strdup(url);
                if (!copy)
                        return -ENOMEM;
        }

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        return free_and_replace(table_get_data(t, cell)->url, copy);
}

int table_set_uppercase(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->uppercase == b)
                return 0;

        d->formatted = mfree(d->formatted);
        d->uppercase = b;
        return 1;
}

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
