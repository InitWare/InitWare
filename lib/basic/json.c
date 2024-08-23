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

#include <sys/types.h>
#include <math.h>

#include "alloc-util.h"
#include "json.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "utf8.h"
#include "util.h"

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

static int
json_parse_string(const char **p, char **ret)
{
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

			*ret = s;
			s = NULL;
			return JSON_STRING;
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
				uint16_t x;
				int r;

				r = unhex_ucs2(c + 1, &x);
				if (r < 0)
					return r;

				c += 5;

				if (!GREEDY_REALLOC(s, n + 4))
					return -ENOMEM;

				if (!utf16_is_surrogate(x))
					n += utf8_encode_unichar(s + n, x);
				else if (utf16_is_trailing_surrogate(x))
					return -EINVAL;
				else {
					uint16_t y;

					if (c[0] != '\\' || c[1] != 'u')
						return -EINVAL;

					r = unhex_ucs2(c + 2, &y);
					if (r < 0)
						return r;

					c += 6;

					if (!utf16_is_trailing_surrogate(y))
						return -EINVAL;

					n += utf8_encode_unichar(s + n,
						utf16_surrogate_pair_to_unichar(
							x, y));
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

		len = utf8_encoded_valid_unichar(c);
		if (len < 0)
			return len;

		if (!GREEDY_REALLOC(s, n + len + 1))
			return -ENOMEM;

		memcpy(s + n, c, len);
		n += len;
		c += len;
	}
}

static int
json_parse_number(const char **p, union json_value *ret)
{
	bool negative = false, exponent_negative = false, is_double = false;
	double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
	intmax_t i = 0;
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
			if (!is_double) {
				int64_t t;

				t = 10 * i + (*c - '0');
				if (t < i) /* overflow */
					is_double = false;
				else
					i = t;
			}

			x = 10.0 * x + (*c - '0');
			c++;
		} while (strchr("0123456789", *c) && *c != 0);
	}

	if (*c == '.') {
		is_double = true;
		c++;

		if (!strchr("0123456789", *c) || *c == 0)
			return -EINVAL;

		do {
			y = 10.0 * y + (*c - '0');
			shift = 10.0 * shift;
			c++;
		} while (strchr("0123456789", *c) && *c != 0);
	}

	if (*c == 'e' || *c == 'E') {
		is_double = true;
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

	if (*c != 0)
		return -EINVAL;

	*p = c;

	if (is_double) {
		ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) *
			exp10((exponent_negative ? -1.0 : 1.0) * exponent);
		return JSON_REAL;
	} else {
		ret->integer = negative ? -i : i;
		return JSON_INTEGER;
	}
}

int
json_tokenize(const char **p, char **ret_string, union json_value *ret_value,
	void **state, unsigned *line)
{
	const char *c;
	int t;
	int r;

	assert(p);
	assert(*p);
	assert(ret_string);
	assert(ret_value);
	assert(state);

	t = PTR_TO_INT(*state);
	c = *p;

	if (t == STATE_NULL) {
		if (line)
			*line = 1;
		t = STATE_VALUE;
	}

	for (;;) {
		const char *b;

		b = c + strspn(c, WHITESPACE);
		if (*b == 0)
			return JSON_END;

		inc_lines(line, c, b - c);
		c = b;

		switch (t) {
		case STATE_VALUE:

			if (*c == '{') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE);
				return JSON_OBJECT_OPEN;

			} else if (*c == '}') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_OBJECT_CLOSE;

			} else if (*c == '[') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE);
				return JSON_ARRAY_OPEN;

			} else if (*c == ']') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_ARRAY_CLOSE;

			} else if (*c == '"') {
				r = json_parse_string(&c, ret_string);
				if (r < 0)
					return r;

				*ret_value = JSON_VALUE_NULL;
				*p = c;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return r;

			} else if (strchr("-0123456789", *c)) {
				r = json_parse_number(&c, ret_value);
				if (r < 0)
					return r;

				*ret_string = NULL;
				*p = c;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return r;

			} else if (startswith(c, "true")) {
				*ret_string = NULL;
				ret_value->boolean = true;
				*p = c + 4;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_BOOLEAN;

			} else if (startswith(c, "false")) {
				*ret_string = NULL;
				ret_value->boolean = false;
				*p = c + 5;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_BOOLEAN;

			} else if (startswith(c, "null")) {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 4;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_NULL;

			} else
				return -EINVAL;

		case STATE_VALUE_POST:

			if (*c == ':') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE);
				return JSON_COLON;
			} else if (*c == ',') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE);
				return JSON_COMMA;
			} else if (*c == '}') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_OBJECT_CLOSE;
			} else if (*c == ']') {
				*ret_string = NULL;
				*ret_value = JSON_VALUE_NULL;
				*p = c + 1;
				*state = INT_TO_PTR(STATE_VALUE_POST);
				return JSON_ARRAY_CLOSE;
			} else
				return -EINVAL;
		}
	}
}
