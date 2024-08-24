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

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sd-id128.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

typedef union JsonValue  {
        /* Encodes a simple value. This structure is generally 8 bytes wide (as double is 64-bit). */
        bool boolean;
        double real;
        int64_t integer;
        uint64_t unsig;
} JsonValue;

typedef struct JsonVariant JsonVariant;

typedef enum JsonVariantType {
        JSON_VARIANT_STRING,
        JSON_VARIANT_INTEGER,
        JSON_VARIANT_UNSIGNED,
        JSON_VARIANT_REAL,
        JSON_VARIANT_NUMBER, /* This a pseudo-type: we can never create variants of this type, but we use it as wildcard check for the above three types */
        JSON_VARIANT_BOOLEAN,
        JSON_VARIANT_ARRAY,
        JSON_VARIANT_OBJECT,
        JSON_VARIANT_NULL,
        _JSON_VARIANT_TYPE_MAX,
        _JSON_VARIANT_TYPE_INVALID = -EINVAL,
} JsonVariantType;

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

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n);
int json_variant_new_base64(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_base32hex(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_hex(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_octescape(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_integer(JsonVariant **ret, int64_t i);
int json_variant_new_unsigned(JsonVariant **ret, uint64_t u);
int json_variant_new_real(JsonVariant **ret, double d);
int json_variant_new_boolean(JsonVariant **ret, bool b);
int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_array_strv(JsonVariant **ret, char **l);
int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_null(JsonVariant **ret);
int json_variant_new_id128(JsonVariant **ret, sd_id128_t id);
int json_variant_new_uuid(JsonVariant **ret, sd_id128_t id);

static inline int json_variant_new_string(JsonVariant **ret, const char *s) {
        return json_variant_new_stringn(ret, s, SIZE_MAX);
}

#define JSON_VALUE_NULL ((union json_value){})

JsonVariant *json_variant_ref(JsonVariant *v);
JsonVariant *json_variant_unref(JsonVariant *v);
void json_variant_unref_many(JsonVariant **array, size_t n);

#define JSON_VARIANT_REPLACE(v, q)        \
        do {                              \
                typeof(v)* _v = &(v);     \
                typeof(q) _q = (q);       \
                json_variant_unref(*_v);  \
                *_v = _q;                 \
        } while(0)

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonVariant *, json_variant_unref);

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

int json_variant_dump(JsonVariant *v, JsonFormatFlags flags, FILE *f, const char *prefix);

int json_variant_append_array(JsonVariant **v, JsonVariant *element);

enum {
        _JSON_BUILD_STRING,
        _JSON_BUILD_INTEGER,
        _JSON_BUILD_UNSIGNED,
        _JSON_BUILD_REAL,
        _JSON_BUILD_BOOLEAN,
        _JSON_BUILD_ARRAY_BEGIN,
        _JSON_BUILD_ARRAY_END,
        _JSON_BUILD_OBJECT_BEGIN,
        _JSON_BUILD_OBJECT_END,
        _JSON_BUILD_PAIR,
        _JSON_BUILD_PAIR_CONDITION,
        _JSON_BUILD_NULL,
        _JSON_BUILD_VARIANT,
        _JSON_BUILD_VARIANT_ARRAY,
        _JSON_BUILD_LITERAL,
        _JSON_BUILD_STRV,
        _JSON_BUILD_STRV_ENV_PAIR,
        _JSON_BUILD_BASE64,
        _JSON_BUILD_IOVEC_BASE64,
        _JSON_BUILD_BASE32HEX,
        _JSON_BUILD_HEX,
        _JSON_BUILD_IOVEC_HEX,
        _JSON_BUILD_OCTESCAPE,
        _JSON_BUILD_ID128,
        _JSON_BUILD_UUID,
        _JSON_BUILD_BYTE_ARRAY,
        _JSON_BUILD_HW_ADDR,
        _JSON_BUILD_STRING_SET,
        _JSON_BUILD_CALLBACK,
        _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO,
        _JSON_BUILD_PAIR_FINITE_USEC,
        _JSON_BUILD_PAIR_STRING_NON_EMPTY,
        _JSON_BUILD_PAIR_STRV_NON_EMPTY,
        _JSON_BUILD_PAIR_VARIANT_NON_NULL,
        _JSON_BUILD_PAIR_VARIANT_ARRAY_NON_EMPTY,
        _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_IN_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_HW_ADDR_NON_NULL,
        _JSON_BUILD_MAX,
};

typedef int (*JsonBuildCallback)(JsonVariant **ret, const char *name, void *userdata);

#define JSON_BUILD_STRING(s) _JSON_BUILD_STRING, (const char*) { s }
#define JSON_BUILD_INTEGER(i) _JSON_BUILD_INTEGER, (int64_t) { i }
#define JSON_BUILD_UNSIGNED(u) _JSON_BUILD_UNSIGNED, (uint64_t) { u }
#define JSON_BUILD_REAL(d) _JSON_BUILD_REAL, (double) { d }
#define JSON_BUILD_BOOLEAN(b) _JSON_BUILD_BOOLEAN, (bool) { b }
#define JSON_BUILD_ARRAY(...) _JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_EMPTY_ARRAY _JSON_BUILD_ARRAY_BEGIN, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_OBJECT(...) _JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_EMPTY_OBJECT _JSON_BUILD_OBJECT_BEGIN, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_PAIR(n, ...) _JSON_BUILD_PAIR, (const char*) { n }, __VA_ARGS__
#define JSON_BUILD_PAIR_CONDITION(c, n, ...) _JSON_BUILD_PAIR_CONDITION, (bool) { c }, (const char*) { n }, __VA_ARGS__
#define JSON_BUILD_NULL _JSON_BUILD_NULL
#define JSON_BUILD_VARIANT(v) _JSON_BUILD_VARIANT, (JsonVariant*) { v }
#define JSON_BUILD_VARIANT_ARRAY(v, n) _JSON_BUILD_VARIANT_ARRAY, (JsonVariant **) { v }, (size_t) { n }
#define JSON_BUILD_LITERAL(l) _JSON_BUILD_LITERAL, (const char*) { l }
#define JSON_BUILD_STRV(l) _JSON_BUILD_STRV, (char**) { l }
#define JSON_BUILD_STRV_ENV_PAIR(l) _JSON_BUILD_STRV_ENV_PAIR, (char**) { l }
#define JSON_BUILD_BASE64(p, n) _JSON_BUILD_BASE64, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_IOVEC_BASE64(iov) _JSON_BUILD_IOVEC_BASE64, (const struct iovec*) { iov }
#define JSON_BUILD_BASE32HEX(p, n) _JSON_BUILD_BASE32HEX, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_HEX(p, n) _JSON_BUILD_HEX, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_IOVEC_HEX(iov) _JSON_BUILD_IOVEC_HEX, (const struct iovec*) { iov }
#define JSON_BUILD_OCTESCAPE(p, n) _JSON_BUILD_OCTESCAPE, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_ID128(id) _JSON_BUILD_ID128, (const sd_id128_t*) { &(id) }
#define JSON_BUILD_UUID(id) _JSON_BUILD_UUID, (const sd_id128_t*) { &(id) }
#define JSON_BUILD_BYTE_ARRAY(v, n) _JSON_BUILD_BYTE_ARRAY, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_CONST_STRING(s) _JSON_BUILD_VARIANT, JSON_VARIANT_STRING_CONST(s)
#define JSON_BUILD_IN4_ADDR(v) JSON_BUILD_BYTE_ARRAY((const struct in_addr*) { v }, sizeof(struct in_addr))
#define JSON_BUILD_IN6_ADDR(v) JSON_BUILD_BYTE_ARRAY((const struct in6_addr*) { v }, sizeof(struct in6_addr))
#define JSON_BUILD_IN_ADDR(v, f) JSON_BUILD_BYTE_ARRAY(((const union in_addr_union*) { v })->bytes, FAMILY_ADDRESS_SIZE_SAFE(f))
#define JSON_BUILD_ETHER_ADDR(v) JSON_BUILD_BYTE_ARRAY(((const struct ether_addr*) { v })->ether_addr_octet, sizeof(struct ether_addr))
#define JSON_BUILD_HW_ADDR(v) _JSON_BUILD_HW_ADDR, (const struct hw_addr_data*) { v }
#define JSON_BUILD_STRING_SET(s) _JSON_BUILD_STRING_SET, (Set *) { s }
#define JSON_BUILD_CALLBACK(c, u) _JSON_BUILD_CALLBACK, (JsonBuildCallback) { c }, (void*) { u }

#define JSON_BUILD_PAIR_STRING(name, s) JSON_BUILD_PAIR(name, JSON_BUILD_STRING(s))
#define JSON_BUILD_PAIR_INTEGER(name, i) JSON_BUILD_PAIR(name, JSON_BUILD_INTEGER(i))
#define JSON_BUILD_PAIR_UNSIGNED(name, u) JSON_BUILD_PAIR(name, JSON_BUILD_UNSIGNED(u))
#define JSON_BUILD_PAIR_REAL(name, d) JSON_BUILD_PAIR(name, JSON_BUILD_REAL(d))
#define JSON_BUILD_PAIR_BOOLEAN(name, b) JSON_BUILD_PAIR(name, JSON_BUILD_BOOLEAN(b))
#define JSON_BUILD_PAIR_ARRAY(name, ...) JSON_BUILD_PAIR(name, JSON_BUILD_ARRAY(__VA_ARGS__))
#define JSON_BUILD_PAIR_EMPTY_ARRAY(name) JSON_BUILD_PAIR(name, JSON_BUILD_EMPTY_ARRAY)
#define JSON_BUILD_PAIR_OBJECT(name, ...) JSON_BUILD_PAIR(name, JSON_BUILD_OBJECT(__VA_ARGS__))
#define JSON_BUILD_PAIR_EMPTY_OBJECT(name) JSON_BUILD_PAIR(name, JSON_BUILD_EMPTY_OBJECT)
#define JSON_BUILD_PAIR_NULL(name) JSON_BUILD_PAIR(name, JSON_BUILD_NULL)
#define JSON_BUILD_PAIR_VARIANT(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_VARIANT(v))
#define JSON_BUILD_PAIR_VARIANT_ARRAY(name, v, n) JSON_BUILD_PAIR(name, JSON_BUILD_VARIANT_ARRAY(v, n))
#define JSON_BUILD_PAIR_LITERAL(name, l) JSON_BUILD_PAIR(name, JSON_BUILD_LITERAL(l))
#define JSON_BUILD_PAIR_STRV(name, l) JSON_BUILD_PAIR(name, JSON_BUILD_STRV(l))
#define JSON_BUILD_PAIR_BASE64(name, p, n) JSON_BUILD_PAIR(name, JSON_BUILD_BASE64(p, n))
#define JSON_BUILD_PAIR_IOVEC_BASE64(name, iov) JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_BASE64(iov))
#define JSON_BUILD_PAIR_HEX(name, p, n) JSON_BUILD_PAIR(name, JSON_BUILD_HEX(p, n))
#define JSON_BUILD_PAIR_IOVEC_HEX(name, iov) JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_HEX(iov))
#define JSON_BUILD_PAIR_ID128(name, id) JSON_BUILD_PAIR(name, JSON_BUILD_ID128(id))
#define JSON_BUILD_PAIR_UUID(name, id) JSON_BUILD_PAIR(name, JSON_BUILD_UUID(id))
#define JSON_BUILD_PAIR_BYTE_ARRAY(name, v, n) JSON_BUILD_PAIR(name, JSON_BUILD_BYTE_ARRAY(v, n))
#define JSON_BUILD_PAIR_IN4_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_IN4_ADDR(v))
#define JSON_BUILD_PAIR_IN6_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_IN6_ADDR(v))
#define JSON_BUILD_PAIR_IN_ADDR(name, v, f) JSON_BUILD_PAIR(name, JSON_BUILD_IN_ADDR(v, f))
#define JSON_BUILD_PAIR_ETHER_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_ETHER_ADDR(v))
#define JSON_BUILD_PAIR_HW_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_HW_ADDR(v))
#define JSON_BUILD_PAIR_STRING_SET(name, s) JSON_BUILD_PAIR(name, JSON_BUILD_STRING_SET(s))
#define JSON_BUILD_PAIR_CALLBACK(name, c, u) JSON_BUILD_PAIR(name, JSON_BUILD_CALLBACK(c, u))

#define JSON_BUILD_PAIR_UNSIGNED_NON_ZERO(name, u) _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO, (const char*) { name }, (uint64_t) { u }
#define JSON_BUILD_PAIR_FINITE_USEC(name, u) _JSON_BUILD_PAIR_FINITE_USEC, (const char*) { name }, (usec_t) { u }
#define JSON_BUILD_PAIR_STRING_NON_EMPTY(name, s) _JSON_BUILD_PAIR_STRING_NON_EMPTY, (const char*) { name }, (const char*) { s }
#define JSON_BUILD_PAIR_STRV_NON_EMPTY(name, l) _JSON_BUILD_PAIR_STRV_NON_EMPTY, (const char*) { name }, (char**) { l }
#define JSON_BUILD_PAIR_VARIANT_NON_NULL(name, v) _JSON_BUILD_PAIR_VARIANT_NON_NULL, (const char*) { name }, (JsonVariant*) { v }
#define JSON_BUILD_PAIR_IN4_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL, (const char*) { name }, (const struct in_addr*) { v }
#define JSON_BUILD_PAIR_IN6_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL, (const char*) { name }, (const struct in6_addr*) { v }
#define JSON_BUILD_PAIR_IN_ADDR_NON_NULL(name, v, f) _JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, (const union in_addr_union*) { v }, (int) { f }
#define JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL, (const char*) { name }, (const struct ether_addr*) { v }
#define JSON_BUILD_PAIR_HW_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_HW_ADDR_NON_NULL, (const char*) { name }, (const struct hw_addr_data*) { v }

int json_build(JsonVariant **ret, ...);
int json_buildv(JsonVariant **ret, va_list ap);
