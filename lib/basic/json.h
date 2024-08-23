#pragma once

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

#include <inttypes.h>
#include <stdbool.h>

enum {
	JSON_END,
	JSON_COLON,
	JSON_COMMA,
	JSON_OBJECT_OPEN,
	JSON_OBJECT_CLOSE,
	JSON_ARRAY_OPEN,
	JSON_ARRAY_CLOSE,
	JSON_STRING,
	JSON_REAL,
	JSON_INTEGER,
	JSON_BOOLEAN,
	JSON_NULL,
};

union json_value {
	bool boolean;
	double real;
	intmax_t integer;
};

#define JSON_VALUE_NULL ((union json_value){})

typedef enum JsonFormatFlags {
        JSON_FORMAT_NEWLINE          = 1 << 0, /* suffix with newline */
        JSON_FORMAT_PRETTY           = 1 << 1, /* add internal whitespace to appeal to human readers */
        JSON_FORMAT_PRETTY_AUTO      = 1 << 2, /* same, but only if connected to a tty (and JSON_FORMAT_NEWLINE otherwise) */
        JSON_FORMAT_COLOR            = 1 << 3, /* insert ANSI color sequences */
        JSON_FORMAT_COLOR_AUTO       = 1 << 4, /* insert ANSI color sequences if colors_enabled() says so */
        JSON_FORMAT_SOURCE           = 1 << 5, /* prefix with source filename/line/column */
        JSON_FORMAT_SSE              = 1 << 6, /* prefix/suffix with W3C server-sent events */
        JSON_FORMAT_SEQ              = 1 << 7, /* prefix/suffix with RFC 7464 application/json-seq */
        JSON_FORMAT_FLUSH            = 1 << 8, /* call fflush() after dumping JSON */
        JSON_FORMAT_EMPTY_ARRAY      = 1 << 9, /* output "[]" for empty input */
        JSON_FORMAT_OFF              = 1 << 10, /* make json_variant_format() fail with -ENOEXEC */
        JSON_FORMAT_CENSOR_SENSITIVE = 1 << 11, /* Replace all sensitive elements with the string "<sensitive data>" */
} JsonFormatFlags;

int json_tokenize(const char **p, char **ret_string,
	union json_value *ret_value, void **state, unsigned *line);
