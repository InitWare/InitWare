/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <float.h>
#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <math.h>
#include <uchar.h>

#include "alloc-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "json.h"
#include "log.h"
#include "macro.h"
#include "math-util.h"
#include "set.h"
#include "string-util.h"
#include "terminal-util.h"
#include "utf8.h"
#include "util.h"

/* Refuse putting together variants with a larger depth than 2K by default (as a protection against overflowing stacks
 * if code processes JSON objects recursively. Note that we store the depth in an uint16_t, hence make sure this
 * remains under 2^16.
 *
 * The value first was 16k, but it was discovered to be too high on llvm/x86-64. See also:
 * https://github.com/systemd/systemd/issues/10738
 *
 * The value then was 4k, but it was discovered to be too high on s390x/aarch64. See also:
 * https://github.com/systemd/systemd/issues/14396 */

#define DEPTH_MAX (2U*1024U)
assert_cc(DEPTH_MAX <= UINT16_MAX);

typedef struct JsonSource {
        /* When we parse from a file or similar, encodes the filename, to indicate the source of a json variant */
        unsigned n_ref;
        unsigned max_line;
        unsigned max_column;
        char name[];
} JsonSource;

/* On x86-64 this whole structure should have a size of 6 * 64 bit = 48 bytes */
struct JsonVariant {
        union {
                /* We either maintain a reference counter for this variant itself, or we are embedded into an
                 * array/object, in which case only that surrounding object is ref-counted. (If 'embedded' is false,
                 * see below.) */
                unsigned n_ref;

                /* If this JsonVariant is part of an array/object, then this field points to the surrounding
                 * JSON_VARIANT_ARRAY/JSON_VARIANT_OBJECT object. (If 'embedded' is true, see below.) */
                JsonVariant *parent;
        };

        /* If this was parsed from some file or buffer, this stores where from, as well as the source line/column */
        JsonSource *source;
        unsigned line, column;

        /* The current 'depth' of the JsonVariant, i.e. how many levels of member variants this has */
        uint16_t depth;

        JsonVariantType type:8;

        /* A marker whether this variant is embedded into in array/object or not. If true, the 'parent' pointer above
         * is valid. If false, the 'n_ref' field above is valid instead. */
        bool is_embedded:1;

        /* In some conditions (for example, if this object is part of an array of strings or objects), we don't store
         * any data inline, but instead simply reference an external object and act as surrogate of it. In that case
         * this bool is set, and the external object is referenced through the .reference field below. */
        bool is_reference:1;

        /* While comparing two arrays, we use this for marking what we already have seen */
        bool is_marked:1;

        /* Erase from memory when freeing */
        bool sensitive:1;

        /* True if we know that any referenced json object is marked sensitive */
        bool recursive_sensitive:1;

        /* If this is an object the fields are strictly ordered by name */
        bool sorted:1;

        /* If in addition to this object all objects referenced by it are also ordered strictly by name */
        bool normalized:1;

        union {
                /* For simple types we store the value in-line. */
                JsonValue value;

                /* For objects and arrays we store the number of elements immediately following */
                size_t n_elements;

                /* If is_reference as indicated above is set, this is where the reference object is actually stored. */
                JsonVariant *reference;

                /* Strings are placed immediately after the structure. Note that when this is a JsonVariant
                 * embedded into an array we might encode strings up to INLINE_STRING_LENGTH characters
                 * directly inside the element, while longer strings are stored as references. When this
                 * object is not embedded into an array, but stand-alone, we allocate the right size for the
                 * whole structure, i.e. the array might be much larger than INLINE_STRING_LENGTH. */
                DECLARE_FLEX_ARRAY(char, string);
        };
};

enum {
	STATE_NULL,
	STATE_VALUE,
	STATE_VALUE_POST,
};

typedef enum JsonExpect {
        /* The following values are used by json_parse() */
        EXPECT_TOPLEVEL,
        EXPECT_END,
        EXPECT_OBJECT_FIRST_KEY,
        EXPECT_OBJECT_NEXT_KEY,
        EXPECT_OBJECT_COLON,
        EXPECT_OBJECT_VALUE,
        EXPECT_OBJECT_COMMA,
        EXPECT_ARRAY_FIRST_ELEMENT,
        EXPECT_ARRAY_NEXT_ELEMENT,
        EXPECT_ARRAY_COMMA,

        /* And these are used by json_build() */
        EXPECT_ARRAY_ELEMENT,
        EXPECT_OBJECT_KEY,
} JsonExpect;

typedef struct JsonStack {
        JsonExpect expect;
        JsonVariant **elements;
        size_t n_elements;
        unsigned line_before;
        unsigned column_before;
        size_t n_suppress; /* When building: if > 0, suppress this many subsequent elements. If == SIZE_MAX, suppress all subsequent elements */
} JsonStack;

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(JsonSource, json_source, mfree);

static bool json_source_equal(JsonSource *a, JsonSource *b) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        return streq(a->name, b->name);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonSource*, json_source_unref);

static void json_stack_release(JsonStack *s) {
        assert(s);

        CLEANUP_ARRAY(s->elements, s->n_elements, json_variant_unref_many);
}

static bool json_variant_is_magic(const JsonVariant *v) {
        if (!v)
                return false;

        return v < _JSON_VARIANT_MAGIC_MAX;
}

static bool json_variant_is_const_string(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        /* A proper JsonVariant is aligned to whatever malloc() aligns things too, which is definitely not uneven. We
         * hence use all uneven pointers as indicators for const strings. */

        return (((uintptr_t) v) & 1) != 0;
}

static bool json_variant_is_regular(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        return (((uintptr_t) v) & 1) == 0;
}

static JsonVariant *json_variant_dereference(JsonVariant *v) {

        /* Recursively dereference variants that are references to other variants */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (!v->is_reference)
                return v;

        return json_variant_dereference(v->reference);
}

static uint16_t json_variant_depth(JsonVariant *v) {

        v = json_variant_dereference(v);
        if (!v)
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        return v->depth;
}

static void inc_lines_columns(unsigned *line, unsigned *column, const char *s, size_t n) {
        assert(line);
        assert(column);
        assert(s || n == 0);

        while (n > 0) {
                if (*s == '\n') {
                        (*line)++;
                        *column = 1;
                } else if ((signed char) *s >= 0 && *s < 127) /* Process ASCII chars quickly */
                        (*column)++;
                else {
                        int w;

                        w = utf8_encoded_valid_unichar(s, n);
                        if (w < 0) /* count invalid unichars as normal characters */
                                w = 1;
                        else if ((size_t) w > n) /* never read more than the specified number of characters */
                                w = (int) n;

                        (*column)++;

                        s += w;
                        n -= w;
                        continue;
                }

                s++;
                n--;
        }
}

/* Inside string arrays we have a series of JsonVariant structures one after the other. In this case, strings longer
 * than INLINE_STRING_MAX are stored as references, and all shorter ones inline. (This means — on x86-64 — strings up
 * to 7 chars are stored within the array elements, and all others in separate allocations) */
#define INLINE_STRING_MAX (sizeof(JsonVariant) - offsetof(JsonVariant, string) - 1U)

static JsonSource* json_source_new(const char *name) {
        JsonSource *s;

        assert(name);

        s = malloc(offsetof(JsonSource, name) + strlen(name) + 1);
        if (!s)
                return NULL;

        *s = (JsonSource) {
                .n_ref = 1,
        };
        strcpy(s->name, name);

        return s;
}

static JsonVariant *json_variant_formalize(JsonVariant *v) {

        /* Converts json variant pointers to their normalized form, i.e. fully dereferenced and wherever
         * possible converted to the "magic" version if there is one */

        if (!v)
                return NULL;

        v = json_variant_dereference(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(v) ? JSON_VARIANT_MAGIC_TRUE : JSON_VARIANT_MAGIC_FALSE;

        case JSON_VARIANT_NULL:
                return JSON_VARIANT_MAGIC_NULL;

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_INTEGER : v;

        case JSON_VARIANT_UNSIGNED:
                return json_variant_unsigned(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_UNSIGNED : v;

        case JSON_VARIANT_REAL:
                return iszero_safe(json_variant_real(v)) ? JSON_VARIANT_MAGIC_ZERO_REAL : v;

        case JSON_VARIANT_STRING:
                return isempty(json_variant_string(v)) ? JSON_VARIANT_MAGIC_EMPTY_STRING : v;

        case JSON_VARIANT_ARRAY:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_ARRAY : v;

        case JSON_VARIANT_OBJECT:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_OBJECT : v;

        default:
                return v;
        }
}

static void json_variant_propagate_sensitive(JsonVariant *from, JsonVariant *to) {
        if (json_variant_is_sensitive(from))
                json_variant_sensitive(to);
}

static int json_variant_copy(JsonVariant **nv, JsonVariant *v) {
        JsonVariantType t;
        JsonVariant *c;
        JsonValue value;
        const void *source;
        size_t k;

        assert(nv);
        assert(v);

        /* Let's copy the simple types literally, and the larger types by references */
        t = json_variant_type(v);
        switch (t) {
        case JSON_VARIANT_INTEGER:
                k = sizeof(int64_t);
                value.integer = json_variant_integer(v);
                source = &value;
                break;

        case JSON_VARIANT_UNSIGNED:
                k = sizeof(uint64_t);
                value.unsig = json_variant_unsigned(v);
                source = &value;
                break;

        case JSON_VARIANT_REAL:
                k = sizeof(double);
                value.real = json_variant_real(v);
                source = &value;
                break;

        case JSON_VARIANT_BOOLEAN:
                k = sizeof(bool);
                value.boolean = json_variant_boolean(v);
                source = &value;
                break;

        case JSON_VARIANT_NULL:
                k = 0;
                source = NULL;
                break;

        case JSON_VARIANT_STRING:
                source = json_variant_string(v);
                k = strnlen(source, INLINE_STRING_MAX + 1);
                if (k <= INLINE_STRING_MAX) {
                        k++;
                        break;
                }

                _fallthrough_;

        default:
                /* Everything else copy by reference */

                c = malloc0(MAX(sizeof(JsonVariant),
                                offsetof(JsonVariant, reference) + sizeof(JsonVariant*)));
                if (!c)
                        return -ENOMEM;

                c->n_ref = 1;
                c->type = t;
                c->is_reference = true;
                c->reference = json_variant_ref(json_variant_formalize(v));

                *nv = c;
                return 0;
        }

        c = malloc0(MAX(sizeof(JsonVariant),
                        offsetof(JsonVariant, value) + k));
        if (!c)
                return -ENOMEM;

        c->n_ref = 1;
        c->type = t;

        memcpy_safe(&c->value, source, k);

        json_variant_propagate_sensitive(v, c);

        *nv = c;
        return 0;
}

static bool json_single_ref(JsonVariant *v) {

        /* Checks whether the caller is the single owner of the object, i.e. can get away with changing it */

        if (!json_variant_is_regular(v))
                return false;

        if (v->is_embedded)
                return json_single_ref(v->parent);

        assert(v->n_ref > 0);
        return v->n_ref == 1;
}

static int json_variant_set_source(JsonVariant **v, JsonSource *source, unsigned line, unsigned column) {
        JsonVariant *w;
        int r;

        assert(v);

        /* Patch in source and line/column number. Tries to do this in-place if the caller is the sole
         * referencer of the object. If not, allocates a new object, possibly a surrogate for the original
         * one */

        if (!*v)
                return 0;

        if (source && line > source->max_line)
                source->max_line = line;
        if (source && column > source->max_column)
                source->max_column = column;

        if (!json_variant_is_regular(*v)) {

                if (!source && line == 0 && column == 0)
                        return 0;

        } else {
                if (json_source_equal((*v)->source, source) &&
                    (*v)->line == line &&
                    (*v)->column == column)
                        return 0;

                if (json_single_ref(*v)) { /* Sole reference? */
                        json_source_unref((*v)->source);
                        (*v)->source = json_source_ref(source);
                        (*v)->line = line;
                        (*v)->column = column;
                        return 1;
                }
        }

        r = json_variant_copy(&w, *v);
        if (r < 0)
                return r;

        assert(json_variant_is_regular(w));
        assert(!w->is_embedded);
        assert(w->n_ref == 1);
        assert(!w->source);

        w->source = json_source_ref(source);
        w->line = line;
        w->column = column;

        JSON_VARIANT_REPLACE(*v, w);

        return 1;
}

static int json_parse_internal(
                const char **input,
                JsonSource *source,
                JsonParseFlags flags,
                JsonVariant **ret,
                unsigned *line,
                unsigned *column,
                bool continue_end) {

        size_t n_stack = 1;
        unsigned line_buffer = 0, column_buffer = 0;
        void *tokenizer_state = NULL;
        JsonStack *stack = NULL;
        const char *p;
        int r;

        assert_return(input, -EINVAL);
        assert_return(ret, -EINVAL);

        p = *input;

        if (!GREEDY_REALLOC(stack, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        if (!line)
                line = &line_buffer;
        if (!column)
                column = &column_buffer;

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *add = NULL;
                _cleanup_free_ char *string = NULL;
                unsigned line_token, column_token;
                JsonStack *current;
                JsonValue value;
                int token;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (continue_end && current->expect == EXPECT_END)
                        goto done;

                token = json_tokenize(&p, &string, &value, &line_token, &column_token, &tokenizer_state, line, column);
                if (token < 0) {
                        r = token;
                        goto finish;
                }

                switch (token) {

                case JSON_TOKEN_END:
                        if (current->expect != EXPECT_END) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(current->n_elements == 1);
                        assert(n_stack == 1);
                        goto done;

                case JSON_TOKEN_COLON:

                        if (current->expect != EXPECT_OBJECT_COLON) {
                                r = -EINVAL;
                                goto finish;
                        }

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;

                case JSON_TOKEN_COMMA:

                        if (current->expect == EXPECT_OBJECT_COMMA)
                                current->expect = EXPECT_OBJECT_NEXT_KEY;
                        else if (current->expect == EXPECT_ARRAY_COMMA)
                                current->expect = EXPECT_ARRAY_NEXT_ELEMENT;
                        else {
                                r = -EINVAL;
                                goto finish;
                        }

                        break;

                case JSON_TOKEN_OBJECT_OPEN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_FIRST_KEY,
                                .line_before = line_token,
                                .column_before = column_token,
                        };

                        current = stack + n_stack - 1;
                        break;

                case JSON_TOKEN_OBJECT_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_object(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        line_token = current->line_before;
                        column_token = current->column_before;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case JSON_TOKEN_ARRAY_OPEN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_FIRST_ELEMENT,
                                .line_before = line_token,
                                .column_before = column_token,
                        };

                        break;

                case JSON_TOKEN_ARRAY_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_array(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        line_token = current->line_before;
                        column_token = current->column_before;

                        json_stack_release(current);
                        n_stack--, current--;
                        break;

                case JSON_TOKEN_STRING:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_string(&add, string);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY))
                                current->expect = EXPECT_OBJECT_COLON;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_REAL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_real(&add, value.real);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_INTEGER:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_integer(&add, value.integer);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_UNSIGNED:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_unsigned(&add, value.unsig);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_BOOLEAN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_boolean(&add, value.boolean);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_NULL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_null(&add);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                default:
                        assert_not_reached();
                }

                if (add) {
                        /* If we are asked to make this parsed object sensitive, then let's apply this
                         * immediately after allocating each variant, so that when we abort half-way
                         * everything we already allocated that is then freed is correctly marked. */
                        if (FLAGS_SET(flags, JSON_PARSE_SENSITIVE))
                                json_variant_sensitive(add);

                        (void) json_variant_set_source(&add, source, line_token, column_token);

                        if (!GREEDY_REALLOC(current->elements, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        *input = p;
        r = 0;

finish:
        for (size_t i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_parse_with_source(
                const char *input,
                const char *source,
                JsonParseFlags flags,
                JsonVariant **ret,
                unsigned *ret_line,
                unsigned *ret_column) {

        _cleanup_(json_source_unrefp) JsonSource *s = NULL;

        if (source) {
                s = json_source_new(source);
                if (!s)
                        return -ENOMEM;
        }

        return json_parse_internal(&input, s, flags, ret, ret_line, ret_column, false);
}

static void
inc_lines(unsigned *line, const char *s, size_t n)
{
	const char *p = s;

	if (!line)
		return;

	for (;;) {
		const char *f;

		f = memchr(p, '\n', n);
		if (!f)
			return;

		n -= (f - p) + 1;
		p = f + 1;
		(*line)++;
	}
}

static int
unhex_ucs2(const char *c, uint16_t *ret)
{
	int aa, bb, cc, dd;
	uint16_t x;

	assert(c);
	assert(ret);

	aa = unhexchar(c[0]);
	if (aa < 0)
		return -EINVAL;

	bb = unhexchar(c[1]);
	if (bb < 0)
		return -EINVAL;

	cc = unhexchar(c[2]);
	if (cc < 0)
		return -EINVAL;

	dd = unhexchar(c[3]);
	if (dd < 0)
		return -EINVAL;

	x = ((uint16_t)aa << 12) | ((uint16_t)bb << 8) | ((uint16_t)cc << 4) |
		((uint16_t)dd);

	if (x <= 0)
		return -EINVAL;

	*ret = x;

	return 0;
}

static int json_parse_string(const char **p, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t n = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c != '"')
                return -EINVAL;

        c++;

        for (;;) {
                int len;

                /* Check for EOF */
                if (*c == 0)
                        return -EINVAL;

                /* Check for control characters 0x00..0x1f */
                if (*c > 0 && *c < ' ')
                        return -EINVAL;

                /* Check for control character 0x7f */
                if (*c == 0x7f)
                        return -EINVAL;

                if (*c == '"') {
                        if (!s) {
                                s = strdup("");
                                if (!s)
                                        return -ENOMEM;
                        } else
                                s[n] = 0;

                        *p = c + 1;

                        *ret = TAKE_PTR(s);
                        return JSON_TOKEN_STRING;
                }

                if (*c == '\\') {
                        char ch = 0;
                        c++;

                        if (*c == 0)
                                return -EINVAL;

                        if (IN_SET(*c, '"', '\\', '/'))
                                ch = *c;
                        else if (*c == 'b')
                                ch = '\b';
                        else if (*c == 'f')
                                ch = '\f';
                        else if (*c == 'n')
                                ch = '\n';
                        else if (*c == 'r')
                                ch = '\r';
                        else if (*c == 't')
                                ch = '\t';
                        else if (*c == 'u') {
                                char16_t x;
                                int r;

                                r = unhex_ucs2(c + 1, &x);
                                if (r < 0)
                                        return r;

                                c += 5;

                                if (!GREEDY_REALLOC(s, n + 5))
                                        return -ENOMEM;

                                if (!utf16_is_surrogate(x))
                                        n += utf8_encode_unichar(s + n, (char32_t) x);
                                else if (utf16_is_trailing_surrogate(x))
                                        return -EINVAL;
                                else {
                                        char16_t y;

                                        if (c[0] != '\\' || c[1] != 'u')
                                                return -EINVAL;

                                        r = unhex_ucs2(c + 2, &y);
                                        if (r < 0)
                                                return r;

                                        c += 6;

                                        if (!utf16_is_trailing_surrogate(y))
                                                return -EINVAL;

                                        n += utf8_encode_unichar(s + n, utf16_surrogate_pair_to_unichar(x, y));
                                }

                                continue;
                        } else
                                return -EINVAL;

                        if (!GREEDY_REALLOC(s, n + 2))
                                return -ENOMEM;

                        s[n++] = ch;
                        c++;
                        continue;
                }

                len = utf8_encoded_valid_unichar(c, SIZE_MAX);
                if (len < 0)
                        return len;

                if (!GREEDY_REALLOC(s, n + len + 1))
                        return -ENOMEM;

                memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int json_parse_number(const char **p, JsonValue *ret) {
        bool negative = false, exponent_negative = false, is_real = false;
        double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
        int64_t i = 0;
        uint64_t u = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c == '-') {
                negative = true;
                c++;
        }

        if (*c == '0')
                c++;
        else {
                if (!strchr("123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        if (!is_real) {
                                if (negative) {

                                        if (i < INT64_MIN / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                int64_t t = 10 * i;

                                                if (t < INT64_MIN + (*c - '0')) /* overflow */
                                                        is_real = true;
                                                else
                                                        i = t - (*c - '0');
                                        }
                                } else {
                                        if (u > UINT64_MAX / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                uint64_t t = 10 * u;

                                                if (t > UINT64_MAX - (*c - '0')) /* overflow */
                                                        is_real = true;
                                                else
                                                        u = t + (*c - '0');
                                        }
                                }
                        }

                        x = 10.0 * x + (*c - '0');

                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == '.') {
                is_real = true;
                c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        y = 10.0 * y + (*c - '0');
                        shift = 10.0 * shift;
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (IN_SET(*c, 'e', 'E')) {
                is_real = true;
                c++;

                if (*c == '-') {
                        exponent_negative = true;
                        c++;
                } else if (*c == '+')
                        c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        exponent = 10.0 * exponent + (*c - '0');
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        *p = c;

        if (is_real) {
                ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) * exp10((exponent_negative ? -1.0 : 1.0) * exponent);
                return JSON_TOKEN_REAL;
        } else if (negative) {
                ret->integer = i;
                return JSON_TOKEN_INTEGER;
        } else  {
                ret->unsig = u;
                return JSON_TOKEN_UNSIGNED;
        }
}

static int print_source(FILE *f, JsonVariant *v, JsonFormatFlags flags, bool whitespace) {
        size_t w, k;

        if (!FLAGS_SET(flags, JSON_FORMAT_SOURCE|JSON_FORMAT_PRETTY))
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        if (!v->source && v->line == 0 && v->column == 0)
                return 0;

        /* The max width we need to format the line numbers for this source file */
        w = (v->source && v->source->max_line > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_line) :
                DECIMAL_STR_MAX(unsigned)-1;
        k = (v->source && v->source->max_column > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_column) :
                DECIMAL_STR_MAX(unsigned) -1;

        if (whitespace) {
                size_t n = 1 + (v->source ? strlen(v->source->name) : 0) +
                               ((v->source && (v->line > 0 || v->column > 0)) ? 1 : 0) +
                               (v->line > 0 ? w : 0) +
                               (((v->source || v->line > 0) && v->column > 0) ? 1 : 0) +
                               (v->column > 0 ? k : 0) +
                               2;

                for (size_t i = 0; i < n; i++)
                        fputc(' ', f);
        } else {
                fputc('[', f);

                if (v->source)
                        fputs(v->source->name, f);
                if (v->source && (v->line > 0 || v->column > 0))
                        fputc(':', f);
                if (v->line > 0)
                        fprintf(f, "%*u", (int) w, v->line);
                if ((v->source || v->line > 0) || v->column > 0)
                        fputc(':', f);
                if (v->column > 0)
                        fprintf(f, "%*u", (int) k, v->column);

                fputc(']', f);
                fputc(' ', f);
        }

        return 0;
}

static void json_format_string(FILE *f, const char *q, JsonFormatFlags flags) {
        assert(q);

        fputc('"', f);

        if (flags & JSON_FORMAT_COLOR)
                fputs(ansi_green(), f);

        for (; *q; q++)
                switch (*q) {
                case '"':
                        fputs("\\\"", f);
                        break;

                case '\\':
                        fputs("\\\\", f);
                        break;

                case '\b':
                        fputs("\\b", f);
                        break;

                case '\f':
                        fputs("\\f", f);
                        break;

                case '\n':
                        fputs("\\n", f);
                        break;

                case '\r':
                        fputs("\\r", f);
                        break;

                case '\t':
                        fputs("\\t", f);
                        break;

                default:
                        if ((signed char) *q >= 0 && *q < ' ')
                                fprintf(f, "\\u%04x", (unsigned) *q);
                        else
                                fputc(*q, f);
                        break;
                }

        if (flags & JSON_FORMAT_COLOR)
                fputs(ANSI_NORMAL, f);

        fputc('"', f);
}

static int json_format(FILE *f, JsonVariant *v, JsonFormatFlags flags, const char *prefix) {
        int r;

        assert(f);
        assert(v);

        if (FLAGS_SET(flags, JSON_FORMAT_CENSOR_SENSITIVE) && json_variant_is_sensitive(v)) {
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ansi_red(), f);
                fputs("\"<sensitive data>\"", f);
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                return 0;
        }

        switch (json_variant_type(v)) {

        case JSON_VARIANT_REAL: {
                locale_t loc, old_loc;

                loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
                if (loc == (locale_t) 0)
                        return -errno;

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                old_loc = uselocale(loc);
                fprintf(f, "%.*e", DECIMAL_DIG, json_variant_real(v));
                uselocale(old_loc);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                freelocale(loc);
                break;
        }

        case JSON_VARIANT_INTEGER:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                fprintf(f, "%" PRIdMAX, json_variant_integer(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_UNSIGNED:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                fprintf(f, "%" PRIuMAX, json_variant_unsigned(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_BOOLEAN:

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                if (json_variant_boolean(v))
                        fputs("true", f);
                else
                        fputs("false", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                break;

        case JSON_VARIANT_NULL:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                fputs("null", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_STRING:
                json_format_string(f, json_variant_string(v), flags);
                break;

        case JSON_VARIANT_ARRAY: {
                size_t n = json_variant_elements(v);
                if (n == 0)
                        fputs("[]", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("[\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('[', f);
                        }

                        for (size_t i = 0; i < n; i++) {
                                JsonVariant *e;

                                assert_se(e = json_variant_by_index(v, i));

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc(']', f);
                }
                break;
        }

        case JSON_VARIANT_OBJECT: {
                size_t n = json_variant_elements(v);
                if (n == 0)
                        fputs("{}", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("{\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('{', f);
                        }

                        for (size_t i = 0; i < n; i += 2) {
                                JsonVariant *e;

                                e = json_variant_by_index(v, i);

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;

                                fputs(flags & JSON_FORMAT_PRETTY ? " : " : ":", f);

                                r = json_format(f, json_variant_by_index(v, i+1), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc('}', f);
                }
                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

int json_tokenize(
                const char **p,
                char **ret_string,
                JsonValue *ret_value,
                unsigned *ret_line,   /* 'ret_line' returns the line at the beginning of this token */
                unsigned *ret_column,
                void **state,
                unsigned *line,       /* 'line' is used as a line state, it always reflect the line we are at after the token was read */
                unsigned *column) {

        unsigned start_line, start_column;
        const char *start, *c;
        size_t n;
        int t, r;

        enum {
                STATE_NULL,
                STATE_VALUE,
                STATE_VALUE_POST,
        };

        assert(p);
        assert(*p);
        assert(ret_string);
        assert(ret_value);
        assert(ret_line);
        assert(ret_column);
        assert(line);
        assert(column);
        assert(state);

        t = PTR_TO_INT(*state);
        if (t == STATE_NULL) {
                *line = 1;
                *column = 1;
                t = STATE_VALUE;
        }

        /* Skip over the whitespace */
        n = strspn(*p, WHITESPACE);
        inc_lines_columns(line, column, *p, n);
        c = *p + n;

        /* Remember where we started processing this token */
        start = c;
        start_line = *line;
        start_column = *column;

        if (*c == 0) {
                *ret_string = NULL;
                *ret_value = JSON_VALUE_NULL;
                r = JSON_TOKEN_END;
                goto finish;
        }

        switch (t) {

        case STATE_VALUE:

                if (*c == '{') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_OBJECT_OPEN;
                        goto null_return;

                } else if (*c == '}') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_OBJECT_CLOSE;
                        goto null_return;

                } else if (*c == '[') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_ARRAY_OPEN;
                        goto null_return;

                } else if (*c == ']') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_ARRAY_CLOSE;
                        goto null_return;

                } else if (*c == '"') {

                        r = json_parse_string(&c, ret_string);
                        if (r < 0)
                                return r;

                        *ret_value = JSON_VALUE_NULL;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        goto finish;

                } else if (strchr("-0123456789", *c)) {

                        r = json_parse_number(&c, ret_value);
                        if (r < 0)
                                return r;

                        *ret_string = NULL;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        goto finish;

                } else if (startswith(c, "true")) {
                        *ret_string = NULL;
                        ret_value->boolean = true;
                        c += 4;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_BOOLEAN;
                        goto finish;

                } else if (startswith(c, "false")) {
                        *ret_string = NULL;
                        ret_value->boolean = false;
                        c += 5;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_BOOLEAN;
                        goto finish;

                } else if (startswith(c, "null")) {
                        *ret_string = NULL;
                        *ret_value = JSON_VALUE_NULL;
                        c += 4;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_NULL;
                        goto finish;

                }

                return -EINVAL;

        case STATE_VALUE_POST:

                if (*c == ':') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_COLON;
                        goto null_return;

                } else if (*c == ',') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_COMMA;
                        goto null_return;

                } else if (*c == '}') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_OBJECT_CLOSE;
                        goto null_return;

                } else if (*c == ']') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_ARRAY_CLOSE;
                        goto null_return;
                }

                return -EINVAL;

        default:
                assert_not_reached();
        }

null_return:
        *ret_string = NULL;
        *ret_value = JSON_VALUE_NULL;

finish:
        inc_lines_columns(line, column, start, c - start);
        *p = c;

        *ret_line = start_line;
        *ret_column = start_column;

        return r;
}

int json_buildv(JsonVariant **ret, va_list ap) {
        JsonStack *stack = NULL;
        size_t n_stack = 1;
        const char *name = NULL;
        int r;

        assert_return(ret, -EINVAL);

        if (!GREEDY_REALLOC(stack, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *add = NULL, *add_more = NULL;
                size_t n_subtract = 0; /* how much to subtract from current->n_suppress, i.e. how many elements would
                                        * have been added to the current variant */
                JsonStack *current;
                int command;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (current->expect == EXPECT_END)
                        goto done;

                command = va_arg(ap, int);

                switch (command) {

                case _JSON_BUILD_STRING: {
                        const char *p;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, p);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_INTEGER: {
                        int64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, int64_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_integer(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_UNSIGNED: {
                        uint64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, uint64_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_unsigned(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_REAL: {
                        double d;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        d = va_arg(ap, double);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_real(&add, d);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BOOLEAN: {
                        bool b;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_boolean(&add, b);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_NULL:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = json_variant_new_null(&add);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        /* Note that we don't care for current->n_suppress here, after all the variant is already
                         * allocated anyway... */
                        add = va_arg(ap, JsonVariant*);
                        if (!add)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else
                                json_variant_ref(add);

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT_ARRAY: {
                        JsonVariant **array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, JsonVariant**);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array(&add, array, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_LITERAL: {
                        const char *l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, const char *);

                        if (l) {
                                /* Note that we don't care for current->n_suppress here, we should generate parsing
                                 * errors even in suppressed object properties */

                                r = json_parse(l, 0, &add, NULL, NULL);
                                if (r < 0)
                                        goto finish;
                        } else
                                add = JSON_VARIANT_MAGIC_NULL;

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ARRAY_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_ELEMENT,
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* if we shall suppress the
                                                                                           * new array, then we should
                                                                                           * also suppress all array
                                                                                           * members */
                        };

                        break;

                case _JSON_BUILD_ARRAY_END:
                        if (current->expect != EXPECT_ARRAY_ELEMENT) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_STRV: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_strv(&add, l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_STRV_ENV_PAIR: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        _cleanup_strv_free_ char **el = NULL;
                        STRV_FOREACH_PAIR(x, y, l) {
                                char *n = NULL;

                                n = strjoin(*x, "=", *y);
                                if (!n) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                r = strv_consume(&el, n);
                                if (r < 0)
                                        goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_strv(&add, el);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BASE64:
                case _JSON_BUILD_BASE32HEX:
                case _JSON_BUILD_HEX:
                case _JSON_BUILD_OCTESCAPE: {
                        const void *p;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const void *);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = command == _JSON_BUILD_BASE64    ? json_variant_new_base64(&add, p, n) :
                                    command == _JSON_BUILD_BASE32HEX ? json_variant_new_base32hex(&add, p, n) :
                                    command == _JSON_BUILD_HEX       ? json_variant_new_hex(&add, p, n) :
                                                                       json_variant_new_octescape(&add, p, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_IOVEC_BASE64:
                case _JSON_BUILD_IOVEC_HEX: {
                        const struct iovec *iov;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        iov = va_arg(ap, const struct iovec*);

                        if (current->n_suppress == 0) {
                                if (iov)
                                        r = command == _JSON_BUILD_IOVEC_BASE64 ? json_variant_new_base64(&add, iov->iov_base, iov->iov_len) :
                                                                                  json_variant_new_hex(&add, iov->iov_base, iov->iov_len);
                                else
                                        r = json_variant_new_string(&add, "");
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ID128:
                case _JSON_BUILD_UUID: {
                        const sd_id128_t *id;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert_se(id = va_arg(ap, sd_id128_t*));

                        if (current->n_suppress == 0) {
                                r = command == _JSON_BUILD_ID128 ?
                                        json_variant_new_id128(&add, *id) :
                                        json_variant_new_uuid(&add, *id);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BYTE_ARRAY: {
                        const void *array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, const void*);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_bytes(&add, array, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_HW_ADDR: {
                        const struct hw_addr_data *hw_addr;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert_se(hw_addr = va_arg(ap, struct hw_addr_data*));

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_bytes(&add, hw_addr->bytes, hw_addr->length);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_STRING_SET: {
                        Set *set;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        set = va_arg(ap, Set*);

                        if (current->n_suppress == 0) {
                                _cleanup_free_ char **sorted = NULL;

                                r = set_dump_sorted(set, (void ***) &sorted, NULL);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_strv(&add, sorted);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_CALLBACK: {
                        JsonBuildCallback cb;
                        void *userdata;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        cb = va_arg(ap, JsonBuildCallback);
                        userdata = va_arg(ap, void *);

                        if (current->n_suppress == 0) {
                                if (cb) {
                                        r = cb(&add, name, userdata);
                                        if (r < 0)
                                                goto finish;
                                }

                                if (!add)
                                        add = JSON_VARIANT_MAGIC_NULL;

                                name = NULL;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_OBJECT_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_KEY,
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* If we shall suppress the
                                                                                        * new object, then we should
                                                                                        * also suppress all object
                                                                                        * members. */
                        };

                        break;

                case _JSON_BUILD_OBJECT_END:

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_object(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_PAIR: {

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        name = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_CONDITION: {
                        bool b;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);
                        name = va_arg(ap, const char *);

                        if (b && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1; /* we generated one item */

                        if (!b && current->n_suppress != SIZE_MAX)
                                current->n_suppress += 2; /* Suppress this one and the next item */

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO: {
                        const char *n;
                        uint64_t u;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, uint64_t);

                        if (u != 0 && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_FINITE_USEC: {
                        const char *n;
                        usec_t u;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, usec_t);

                        if (u != USEC_INFINITY && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRING_NON_EMPTY: {
                        const char *n, *s;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        s = va_arg(ap, const char *);

                        if (!isempty(s) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_string(&add_more, s);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRV_NON_EMPTY: {
                        const char *n;
                        char **l;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        l = va_arg(ap, char **);

                        if (!strv_isempty(l) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_strv(&add_more, l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_VARIANT_NON_NULL: {
                        JsonVariant *v;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        v = va_arg(ap, JsonVariant *);

                        if (v && !json_variant_is_null(v) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                add_more = json_variant_ref(v);
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL: {
                        const struct in_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct in_addr *);

                        if (a && in4_addr_is_set(a) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_bytes(&add_more, a, sizeof(struct in_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL: {
                        const struct in6_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct in6_addr *);

                        if (a && in6_addr_is_set(a) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_bytes(&add_more, a, sizeof(struct in6_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN_ADDR_NON_NULL: {
                        const union in_addr_union *a;
                        const char *n;
                        int f;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const union in_addr_union *);
                        f = va_arg(ap, int);

                        if (a && in_addr_is_set(f, a) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_bytes(&add_more, a->bytes, FAMILY_ADDRESS_SIZE(f));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL: {
                        const struct ether_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct ether_addr *);

                        if (a && !ether_addr_is_null(a) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_bytes(&add_more, a->ether_addr_octet, sizeof(struct ether_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_HW_ADDR_NON_NULL: {
                        const struct hw_addr_data *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct hw_addr_data *);

                        if (a && !hw_addr_is_null(a) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_bytes(&add_more, a->bytes, a->length);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }
                }

                /* If variants were generated, add them to our current variant, but only if we are not supposed to suppress additions */
                if (add && current->n_suppress == 0) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements + 1 + !!add_more)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                        if (add_more)
                                current->elements[current->n_elements++] = TAKE_PTR(add_more);
                }

                /* If we are supposed to suppress items, let's subtract how many items where generated from
                 * that counter. Except if the counter is SIZE_MAX, i.e. we shall suppress an infinite number
                 * of elements on this stack level */
                if (current->n_suppress != SIZE_MAX) {
                        if (current->n_suppress <= n_subtract) /* Saturated */
                                current->n_suppress = 0;
                        else
                                current->n_suppress -= n_subtract;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        r = 0;

finish:
        for (size_t i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_build(JsonVariant **ret, ...) {
        va_list ap;
        int r;

        va_start(ap, ret);
        r = json_buildv(ret, ap);
        va_end(ap);

        return r;
}

static JsonVariant *json_variant_conservative_formalize(JsonVariant *v) {

        /* Much like json_variant_formalize(), but won't simplify if the variant has a source/line location
         * attached to it, in order not to lose context */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (v->source || v->line > 0 || v->column > 0)
                return v;

        return json_variant_formalize(v);
}

static size_t json_variant_size(JsonVariant* v) {
        if (!json_variant_is_regular(v))
                return 0;

        if (v->is_reference)
                return offsetof(JsonVariant, reference) + sizeof(JsonVariant*);

        switch (v->type) {

        case JSON_VARIANT_STRING:
                return offsetof(JsonVariant, string) + strlen(v->string) + 1;

        case JSON_VARIANT_REAL:
                return offsetof(JsonVariant, value) + sizeof(double);

        case JSON_VARIANT_UNSIGNED:
                return offsetof(JsonVariant, value) + sizeof(uint64_t);

        case JSON_VARIANT_INTEGER:
                return offsetof(JsonVariant, value) + sizeof(int64_t);

        case JSON_VARIANT_BOOLEAN:
                return offsetof(JsonVariant, value) + sizeof(bool);

        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                return offsetof(JsonVariant, n_elements) + sizeof(size_t);

        case JSON_VARIANT_NULL:
                return offsetof(JsonVariant, value);

        default:
                assert_not_reached();
        }
}

int json_variant_dump(JsonVariant *v, JsonFormatFlags flags, FILE *f, const char *prefix) {
        if (!v) {
                if (flags & JSON_FORMAT_EMPTY_ARRAY)
                        v = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                else
                        return 0;
        }

        if (!f)
                f = stdout;

        print_source(f, v, flags, false);

        if (((flags & (JSON_FORMAT_COLOR_AUTO|JSON_FORMAT_COLOR)) == JSON_FORMAT_COLOR_AUTO) && colors_enabled())
                flags |= JSON_FORMAT_COLOR;

        if (((flags & (JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_PRETTY)) == JSON_FORMAT_PRETTY_AUTO))
                flags |= on_tty() ? JSON_FORMAT_PRETTY : JSON_FORMAT_NEWLINE;

        if (flags & JSON_FORMAT_SSE)
                fputs("data: ", f);
        if (flags & JSON_FORMAT_SEQ)
                fputc('\x1e', f); /* ASCII Record Separator */

        json_format(f, v, flags, prefix);

        if (flags & (JSON_FORMAT_PRETTY|JSON_FORMAT_SEQ|JSON_FORMAT_SSE|JSON_FORMAT_NEWLINE))
                fputc('\n', f);
        if (flags & JSON_FORMAT_SSE)
                fputc('\n', f); /* In case of SSE add a second newline */

        if (flags & JSON_FORMAT_FLUSH)
                return fflush_and_check(f);
        return 0;
}

static void json_variant_free_inner(JsonVariant *v, bool force_sensitive) {
        bool sensitive;

        assert(v);

        if (!json_variant_is_regular(v))
                return;

        json_source_unref(v->source);

        sensitive = v->sensitive || force_sensitive;

        if (v->is_reference) {
                if (sensitive)
                        json_variant_sensitive(v->reference);

                json_variant_unref(v->reference);
                return;
        }

        if (IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                for (size_t i = 0; i < v->n_elements; i++)
                        json_variant_free_inner(v + 1 + i, sensitive);

        if (sensitive)
                explicit_bzero_safe(v, json_variant_size(v));
}

JsonVariant *json_variant_ref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return v;

        if (v->is_embedded)
                json_variant_ref(v->parent); /* ref the compounding variant instead */
        else {
                assert(v->n_ref > 0);
                v->n_ref++;
        }

        return v;
}

JsonVariant *json_variant_unref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return NULL;

        if (v->is_embedded)
                json_variant_unref(v->parent);
        else {
                assert(v->n_ref > 0);
                v->n_ref--;

                if (v->n_ref == 0) {
                        json_variant_free_inner(v, false);
                        free(v);
                }
        }

        return NULL;
}

static int json_variant_new(JsonVariant **ret, JsonVariantType type, size_t space) {
        JsonVariant *v;

        assert_return(ret, -EINVAL);

        v = malloc0(MAX(sizeof(JsonVariant),
                        offsetof(JsonVariant, value) + space));
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = type;

        *ret = v;
        return 0;
}

int json_variant_new_integer(JsonVariant **ret, int64_t i) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

        if (i == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_INTEGER;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_INTEGER, sizeof(i));
        if (r < 0)
                return r;

        v->value.integer = i;
        *ret = v;

        return 0;
}

int json_variant_new_unsigned(JsonVariant **ret, uint64_t u) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (u == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_UNSIGNED;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_UNSIGNED, sizeof(u));
        if (r < 0)
                return r;

        v->value.unsig = u;
        *ret = v;

        return 0;
}

int json_variant_new_real(JsonVariant **ret, double d) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

        r = fpclassify(d);
        switch (r) {
        case FP_NAN:
        case FP_INFINITE:
                /* JSON doesn't know NaN, +Infinity or -Infinity. Let's silently convert to 'null'. */
                *ret = JSON_VARIANT_MAGIC_NULL;
                return 0;

        case FP_ZERO:
                *ret = JSON_VARIANT_MAGIC_ZERO_REAL;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_REAL, sizeof(d));
        if (r < 0)
                return r;

        v->value.real = d;
        *ret = v;

        return 0;
}

int json_variant_new_boolean(JsonVariant **ret, bool b) {
        assert_return(ret, -EINVAL);

        if (b)
                *ret = JSON_VARIANT_MAGIC_TRUE;
        else
                *ret = JSON_VARIANT_MAGIC_FALSE;

        return 0;
}

int json_variant_new_null(JsonVariant **ret) {
        assert_return(ret, -EINVAL);

        *ret = JSON_VARIANT_MAGIC_NULL;
        return 0;
}

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (!s) {
                assert_return(IN_SET(n, 0, SIZE_MAX), -EINVAL);
                return json_variant_new_null(ret);
        }
        if (n == SIZE_MAX) /* determine length automatically */
                n = strlen(s);
        else if (memchr(s, 0, n)) /* don't allow embedded NUL, as we can't express that in JSON */
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_STRING;
                return 0;
        }

        if (!utf8_is_valid_n(s, n)) /* JSON strings must be valid UTF-8 */
                return -EUCLEAN;

        r = json_variant_new(&v, JSON_VARIANT_STRING, n + 1);
        if (r < 0)
                return r;

        memcpy(v->string, s, n);
        v->string[n] = 0;

        *ret = v;
        return 0;
}

int json_variant_new_base64(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;
        ssize_t k;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        k = base64mem(p, n, &s);
        if (k < 0)
                return k;

        return json_variant_new_stringn(ret, s, k);
}

int json_variant_new_base32hex(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = base32hexmem(p, n, false);
        if (!s)
                return -ENOMEM;

        return json_variant_new_string(ret, s);
}

int json_variant_new_hex(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = hexmem(p, n);
        if (!s)
                return -ENOMEM;

        return json_variant_new_stringn(ret, s, n*2);
}

int json_variant_new_octescape(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = octescape(p, n);
        if (!s)
                return -ENOMEM;

        return json_variant_new_string(ret, s);
}

int json_variant_new_id128(JsonVariant **ret, sd_id128_t id) {
        return json_variant_new_string(ret, SD_ID128_TO_STRING(id));
}

int json_variant_new_uuid(JsonVariant **ret, sd_id128_t id) {
        return json_variant_new_string(ret, SD_ID128_TO_UUID_STRING(id));
}

static void json_variant_set(JsonVariant *a, JsonVariant *b) {
        assert(a);

        b = json_variant_dereference(b);
        if (!b) {
                a->type = JSON_VARIANT_NULL;
                return;
        }

        a->type = json_variant_type(b);
        switch (a->type) {

        case JSON_VARIANT_INTEGER:
                a->value.integer = json_variant_integer(b);
                break;

        case JSON_VARIANT_UNSIGNED:
                a->value.unsig = json_variant_unsigned(b);
                break;

        case JSON_VARIANT_REAL:
                a->value.real = json_variant_real(b);
                break;

        case JSON_VARIANT_BOOLEAN:
                a->value.boolean = json_variant_boolean(b);
                break;

        case JSON_VARIANT_STRING: {
                const char *s;

                assert_se(s = json_variant_string(b));

                /* Short strings we can store inline */
                if (strnlen(s, INLINE_STRING_MAX+1) <= INLINE_STRING_MAX) {
                        strcpy(a->string, s);
                        break;
                }

                /* For longer strings, use a reference… */
                _fallthrough_;
        }

        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                a->is_reference = true;
                a->reference = json_variant_ref(json_variant_conservative_formalize(b));
                break;

        case JSON_VARIANT_NULL:
                break;

        default:
                assert_not_reached();
        }
}

static void json_variant_copy_source(JsonVariant *v, JsonVariant *from) {
        assert(v);

        if (!json_variant_is_regular(from))
                return;

        v->line = from->line;
        v->column = from->column;
        v->source = json_source_ref(from->source);
}

int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *prev = NULL;
        bool sorted = true, normalized = true;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
                return 0;
        }
        assert_return(array, -EINVAL);
        assert_return(n % 2 == 0, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_OBJECT,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements,
                            *c = array[v->n_elements];
                uint16_t d;

                if ((v->n_elements & 1) == 0) {
                        const char *k;

                        if (!json_variant_is_string(c))
                                return -EINVAL; /* Every second one needs to be a string, as it is the key name */

                        assert_se(k = json_variant_string(c));

                        if (prev && strcmp(k, prev) <= 0)
                                sorted = normalized = false;

                        prev = k;
                } else if (!json_variant_is_normalized(c))
                        normalized = false;

                d = json_variant_depth(c);
                if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                        return -ELNRNG;
                if (d >= v->depth)
                        v->depth = d + 1;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                };

                json_variant_set(w, c);
                json_variant_copy_source(w, c);
        }

        v->normalized = normalized;
        v->sorted = sorted;

        *ret = TAKE_PTR(v);
        return 0;
}

static int _json_variant_array_put_element(JsonVariant *array, JsonVariant *element) {
        assert(array);
        JsonVariant *w = array + 1 + array->n_elements;

        uint16_t d = json_variant_depth(element);
        if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                return -ELNRNG;
        if (d >= array->depth)
                array->depth = d + 1;
        array->n_elements++;

        *w = (JsonVariant) {
                .is_embedded = true,
                .parent = array,
        };

        json_variant_set(w, element);
        json_variant_copy_source(w, element);

        if (!json_variant_is_normalized(element))
                array->normalized = false;

        return 0;
}

int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(array, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .normalized = true,
        };

        while (v->n_elements < n) {
                r = _json_variant_array_put_element(v, array[v->n_elements]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n) {
        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(p, -EINVAL);

        JsonVariant *v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .n_elements = n,
                .depth = 1,
        };

        for (size_t i = 0; i < n; i++) {
                JsonVariant *w = v + 1 + i;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_UNSIGNED,
                        .value.unsig = ((const uint8_t*) p)[i],
                };
        }

        v->normalized = true;

        *ret = v;
        return 0;
}

int json_variant_new_array_strv(JsonVariant **ret, char **l) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        size_t n;
        int r;

        assert(ret);

        n = strv_length(l);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .depth = 1,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements;
                size_t k;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_STRING,
                };

                k = strlen(l[v->n_elements]);

                if (k > INLINE_STRING_MAX) {
                        /* If string is too long, store it as reference. */

                        r = json_variant_new_string(&w->reference, l[v->n_elements]);
                        if (r < 0)
                                return r;

                        w->is_reference = true;
                } else {
                        if (!utf8_is_valid_n(l[v->n_elements], k)) /* JSON strings must be valid UTF-8 */
                                return -EUCLEAN;

                        memcpy(w->string, l[v->n_elements], k+1);
                }
        }

        v->normalized = true;

        *ret = TAKE_PTR(v);
        return 0;
}

void json_variant_unref_many(JsonVariant **array, size_t n) {
        assert(array || n == 0);

        for (size_t i = 0; i < n; i++)
                json_variant_unref(array[i]);

        free(array);
}

const char *json_variant_string(JsonVariant *v) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return "";
        if (json_variant_is_magic(v))
                goto mismatch;
        if (json_variant_is_const_string(v)) {
                uintptr_t p = (uintptr_t) v;

                assert((p & 1) != 0);
                return (const char*) (p ^ 1U);
        }

        if (v->is_reference)
                return json_variant_string(v->reference);
        if (v->type != JSON_VARIANT_STRING)
                goto mismatch;

        return v->string;

mismatch:
        log_debug("Non-string JSON variant requested as string, returning NULL.");
        return NULL;
}

bool json_variant_boolean(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_TRUE)
                return true;
        if (v == JSON_VARIANT_MAGIC_FALSE)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != JSON_VARIANT_BOOLEAN)
                goto mismatch;
        if (v->is_reference)
                return json_variant_boolean(v->reference);

        return v->value.boolean;

mismatch:
        log_debug("Non-boolean JSON variant requested as boolean, returning false.");
        return false;
}

int64_t json_variant_integer(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                return v->value.integer;

        case JSON_VARIANT_UNSIGNED:
                if (v->value.unsig <= INT64_MAX)
                        return (int64_t) v->value.unsig;

                log_debug("Unsigned integer %" PRIu64 " requested as signed integer and out of range, returning 0.", v->value.unsig);
                return 0;

        case JSON_VARIANT_REAL: {
                int64_t converted;

                converted = (int64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0;
}

uint64_t json_variant_unsigned(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                if (v->value.integer >= 0)
                        return (uint64_t) v->value.integer;

                log_debug("Signed integer %" PRIi64 " requested as unsigned integer and out of range, returning 0.", v->value.integer);
                return 0;

        case JSON_VARIANT_UNSIGNED:
                return v->value.unsig;

        case JSON_VARIANT_REAL: {
                uint64_t converted;

                converted = (uint64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as unsigned integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as unsigned, returning 0.");
        return 0;
}

double json_variant_real(JsonVariant *v) {
        if (!v)
                return 0.0;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0.0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_real(v->reference);

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real;

        case JSON_VARIANT_INTEGER: {
                double converted = (double) v->value.integer;

                if ((int64_t) converted == v->value.integer)
                        return converted;

                log_debug("Signed integer %" PRIi64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.integer);
                return 0.0;
        }

        case JSON_VARIANT_UNSIGNED: {
                double converted = (double) v->value.unsig;

                if ((uint64_t) converted == v->value.unsig)
                        return converted;

                log_debug("Unsigned integer %" PRIu64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.unsig);
                return 0.0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0.0;
}

JsonVariantType json_variant_type(JsonVariant *v) {

        if (!v)
                return _JSON_VARIANT_TYPE_INVALID;

        if (json_variant_is_const_string(v))
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_TRUE || v == JSON_VARIANT_MAGIC_FALSE)
                return JSON_VARIANT_BOOLEAN;

        if (v == JSON_VARIANT_MAGIC_NULL)
                return JSON_VARIANT_NULL;

        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER)
                return JSON_VARIANT_INTEGER;

        if (v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED)
                return JSON_VARIANT_UNSIGNED;

        if (v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return JSON_VARIANT_REAL;

        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY)
                return JSON_VARIANT_ARRAY;

        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return JSON_VARIANT_OBJECT;

        return v->type;
}

void json_variant_sensitive(JsonVariant *v) {
        assert(v);

        /* Marks a variant as "sensitive", so that it is erased from memory when it is destroyed. This is a
         * one-way operation: as soon as it is marked this way it remains marked this way until it's
         * destroyed. A magic variant is never sensitive though, even when asked, since it's too
         * basic. Similar, const string variant are never sensitive either, after all they are included in
         * the source code as they are, which is not suitable for inclusion of secrets.
         *
         * Note that this flag has a recursive effect: when we destroy an object or array we'll propagate the
         * flag to all contained variants. And if those are then destroyed this is propagated further down,
         * and so on. */

        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return;

        v->sensitive = true;
}

bool json_variant_is_sensitive(JsonVariant *v) {
        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return false;

        return v->sensitive;
}

bool json_variant_has_type(JsonVariant *v, JsonVariantType type) {
        JsonVariantType rt;

        /* Note: we turn off ubsan float cast overflow detection for this function, since it would complain
         * about our float casts but we do them explicitly to detect conversion errors. */

        v = json_variant_dereference(v);
        if (!v)
                return false;

        rt = json_variant_type(v);
        if (rt == type)
                return true;

        /* If it's a const string, then it only can be a string, and if it is not, it's not */
        if (json_variant_is_const_string(v))
                return false;

        /* All three magic zeroes qualify as integer, unsigned and as real */
        if ((v == JSON_VARIANT_MAGIC_ZERO_INTEGER || v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED || v == JSON_VARIANT_MAGIC_ZERO_REAL) &&
            IN_SET(type, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL, JSON_VARIANT_NUMBER))
                return true;

        /* All other magic variant types are only equal to themselves */
        if (json_variant_is_magic(v))
                return false;

        /* Handle the "number" pseudo type */
        if (type == JSON_VARIANT_NUMBER)
                return IN_SET(rt, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL);

        /* Integer conversions are OK in many cases */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_UNSIGNED)
                return v->value.integer >= 0;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_INTEGER)
                return v->value.unsig <= INT64_MAX;

        /* Any integer that can be converted lossley to a real and back may also be considered a real */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_REAL)
                return (int64_t) (double) v->value.integer == v->value.integer;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_REAL)
                return (uint64_t) (double) v->value.unsig == v->value.unsig;

        /* Any real that can be converted losslessly to an integer and back may also be considered an integer */
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_INTEGER)
                return fp_equal((double) (int64_t) v->value.real, v->value.real);
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_UNSIGNED)
                return fp_equal((double) (uint64_t) v->value.real, v->value.real);

        return false;
}

size_t json_variant_elements(JsonVariant *v) {
        if (!v)
                return 0;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_elements(v->reference);

        return v->n_elements;

mismatch:
        log_debug("Number of elements in non-array/non-object JSON variant requested, returning 0.");
        return 0;
}

JsonVariant *json_variant_by_index(JsonVariant *v, size_t idx) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return NULL;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_by_index(v->reference, idx);
        if (idx >= v->n_elements)
                return NULL;

        return json_variant_conservative_formalize(v + 1 + idx);

mismatch:
        log_debug("Element in non-array/non-object JSON variant requested by index, returning NULL.");
        return NULL;
}

bool json_variant_is_normalized(JsonVariant *v) {
        /* For now, let's consider anything containing numbers not expressible as integers as non-normalized.
         * That's because we cannot sensibly compare them due to accuracy issues, nor even store them if they
         * are too large. */
        if (json_variant_is_real(v) && !json_variant_is_integer(v) && !json_variant_is_unsigned(v))
                return false;

        /* The concept only applies to variants that include other variants, i.e. objects and arrays. All
         * others are normalized anyway. */
        if (!json_variant_is_object(v) && !json_variant_is_array(v))
                return true;

        /* Empty objects/arrays don't include any other variant, hence are always normalized too */
        if (json_variant_elements(v) == 0)
                return true;

        return v->normalized; /* For everything else there's an explicit boolean we maintain */
}

static unsigned json_variant_n_ref(const JsonVariant *v) {
        /* Return the number of references to v.
         * 0  => NULL or not a regular object or embedded.
         * >0 => number of references
         */

        if (!v || !json_variant_is_regular(v) || v->is_embedded)
                return 0;

        assert(v->n_ref > 0);
        return v->n_ref;
}

int json_variant_append_array(JsonVariant **v, JsonVariant *element) {
        _cleanup_(json_variant_unrefp) JsonVariant *nv = NULL;
        bool blank;
        int r;

        assert(v);
        assert(element);

        if (!*v || json_variant_is_null(*v))
                blank = true;
        else if (json_variant_is_array(*v))
                blank = json_variant_elements(*v) == 0;
        else
                return -EINVAL;

        if (blank) {
                r = json_variant_new_array(&nv, (JsonVariant*[]) { element }, 1);
                if (r < 0)
                        return r;
        } else if (json_variant_n_ref(*v) == 1) {
                /* Let's bump the reference count on element. We can't do the realloc if we're appending *v
                 * to itself, or one of the objects embedded in *v to *v. If the reference count grows, we
                 * need to fall back to the other method below. */

                _unused_ _cleanup_(json_variant_unrefp) JsonVariant *dummy = json_variant_ref(element);
                if (json_variant_n_ref(*v) == 1) {
                        /* We hold the only reference. Let's mutate the object. */
                        size_t size = json_variant_elements(*v);
                        void *old = *v;

                        if (!GREEDY_REALLOC(*v, size + 1 + 1))
                                return -ENOMEM;

                        if (old != *v)
                                /* Readjust the parent pointers to the new address */
                                for (size_t i = 1; i < size; i++)
                                        (*v)[1 + i].parent = *v;

                        return _json_variant_array_put_element(*v, element);
                }
        }

        if (!blank) {
                size_t size = json_variant_elements(*v);

                _cleanup_free_ JsonVariant **array = new(JsonVariant*, size + 1);
                if (!array)
                        return -ENOMEM;

                for (size_t i = 0; i < size; i++)
                        array[i] = json_variant_by_index(*v, i);

                array[size] = element;

                r = json_variant_new_array(&nv, array, size + 1);
                if (r < 0)
                        return r;
        }

        json_variant_propagate_sensitive(*v, nv);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(nv));

        return 0;
}
