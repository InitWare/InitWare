#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdbool.h>
#include <uchar.h>

#include "macro.h"

#define UTF8_REPLACEMENT_CHARACTER "\xef\xbf\xbd"
#define UTF8_BYTE_ORDER_MARK "\xef\xbb\xbf"

char *utf8_is_valid_n(const char *str, size_t len_bytes) _pure_;
static inline char *utf8_is_valid(const char *s) {
        return utf8_is_valid_n(s, SIZE_MAX);
}
char *ascii_is_valid(const char *s) _pure_;
char *ascii_is_valid_n(const char *str, size_t len);

bool utf8_is_printable_newline(const char *str, size_t length,
	bool newline) _pure_;
#define utf8_is_printable(str, length)                                         \
	utf8_is_printable_newline(str, length, true)

char *utf8_escape_invalid(const char *s);
char *utf8_escape_non_printable_full(const char *str, size_t console_width, bool force_ellipsis);
static inline char *utf8_escape_non_printable(const char *str) {
        return utf8_escape_non_printable_full(str, SIZE_MAX, false);
}

size_t utf8_encode_unichar(char *out_utf8, uint32_t g);
char *utf16_to_utf8(const void *s, size_t length);

int utf8_encoded_valid_unichar(const char *str, size_t length);
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar);

bool unichar_is_valid(int32_t ch);

static inline bool
utf16_is_surrogate(uint16_t c)
{
	return (0xd800 <= c && c <= 0xdfff);
}

static inline bool
utf16_is_trailing_surrogate(uint16_t c)
{
	return (0xdc00 <= c && c <= 0xdfff);
}

static inline uint32_t
utf16_surrogate_pair_to_unichar(uint16_t lead, uint16_t trail)
{
	return ((lead - 0xd800) << 10) + (trail - 0xdc00) + 0x10000;
}

size_t utf8_console_width(const char *str);
