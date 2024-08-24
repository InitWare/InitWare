#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>

#include "extract-word.h"
#include "string-util.h"
#include "util.h"

char *strv_find(char **l, const char *name) _pure_;
char* strv_find_case(char * const *l, const char *name) _pure_;
char *strv_find_prefix(char **l, const char *name) _pure_;
char *strv_find_startswith(char **l, const char *name) _pure_;

char** strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

void strv_clear(char **l);

char **strv_copy(char *const *l);
unsigned strv_length(char *const *l) _pure_;

int strv_extend_strv(char ***a, char * const *b, bool filter_duplicates);
int strv_extend_strv_biconcat(char ***a, const char *prefix, const char* const *b, const char *suffix);
static inline int strv_extend_strv_concat(char ***a, const char* const *b, const char *suffix) {
        return strv_extend_strv_biconcat(a, NULL, b, suffix);
}

int strv_extend_many_internal(char ***l, const char *value, ...);
#define strv_extend_many(l, ...) strv_extend_many_internal(l, __VA_ARGS__, POINTER_MAX)

int strv_extend(char ***l, const char *value);
int strv_extendf(char ***l, const char *format, ...) _printf_(2, 0);
int strv_push(char ***l, char *value);
int strv_push_pair(char ***l, char *a, char *b);
int strv_push_prepend(char ***l, char *value);
int strv_consume(char ***l, char *value);
int strv_consume_pair(char ***l, char *a, char *b);
int strv_consume_prepend(char ***l, char *value);

int strv_insert(char ***l, size_t position, char *value);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);
bool strv_is_uniq(char **l);

bool strv_equal(char **a, char **b);

#define strv_contains(l, s) (!!strv_find((l), (s)))
#define strv_contains_case(l, s) (!!strv_find_case((l), (s)))

char **strv_new(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);

static inline const char *
STRV_IFNOTNULL(const char *x)
{
	return x ? x : (const char *)-1;
}

static inline bool
strv_isempty(char *const *l)
{
	return !l || !*l;
}

int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags);
static inline char** strv_split(const char *s, const char *separators) {
        char **ret;

        if (strv_split_full(&ret, s, separators, EXTRACT_RETAIN_ESCAPE) < 0)
                return NULL;

        return ret;
}

char **strv_split_newlines(const char *s);

int strv_split_quoted(char ***t, const char *s, bool relax);

char *strv_join(char **l, const char *separator);
char *strv_join_quoted(char **l);

char **strv_parse_nulstr(const char *s, size_t l);
char **strv_split_nulstr(const char *s);

bool strv_overlap(char **a, char **b) _pure_;

#define STRV_FOREACH_BACKWARDS(s, l)                                           \
	STRV_FOREACH (s, l)                                                    \
		;                                                              \
	for ((s)--; (l) && ((s) >= (l)); (s)--)

#define _STRV_FOREACH_PAIR(x, y, l, i)                          \
        for (typeof(*l) *x, *y, *i = (l);                       \
             i && *(x = i) && *(y = i + 1);                     \
             i += 2)

#define STRV_FOREACH_PAIR(x, y, l)                      \
        _STRV_FOREACH_PAIR(x, y, l, UNIQ_T(i, UNIQ))

char **strv_sort(char **l);
void strv_print(char **l);

char* endswith_strv(const char *s, char * const *l);

#define ENDSWITH_SET(p, ...)                                    \
        endswith_strv(p, STRV_MAKE(__VA_ARGS__))	

#define strv_from_stdarg_alloca(first)                                         \
	({                                                                     \
		char **_l;                                                     \
                                                                               \
		if (!first)                                                    \
			_l = (char **)&first;                                  \
		else {                                                         \
			unsigned _n;                                           \
			va_list _ap;                                           \
                                                                               \
			_n = 1;                                                \
			va_start(_ap, first);                                  \
			while (va_arg(_ap, char *))                            \
				_n++;                                          \
			va_end(_ap);                                           \
                                                                               \
			_l = newa(char *, _n + 1);                             \
			_l[_n = 0] = (char *)first;                            \
			va_start(_ap, first);                                  \
			for (;;) {                                             \
				_l[++_n] = va_arg(_ap, char *);                \
				if (!_l[_n])                                   \
					break;                                 \
			}                                                      \
			va_end(_ap);                                           \
		}                                                              \
		_l;                                                            \
	})

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)
#define STRPTR_IN_SET(x, ...)                                    \
      ({                                                       \
              const char* _x = (x);                            \
              _x && strv_contains(STRV_MAKE(__VA_ARGS__), _x); \
      })

#define STRCASE_IN_SET(x, ...) strv_contains_case(STRV_MAKE(__VA_ARGS__), x)

#define _FOREACH_STRING(uniq, x, y, ...)                                \
        for (const char *x, * const*UNIQ_T(l, uniq) = STRV_MAKE_CONST(({ x = y; }), ##__VA_ARGS__); \
             x;                                                         \
             x = *(++UNIQ_T(l, uniq)))

#define FOREACH_STRING(x, y, ...)                       \
        _FOREACH_STRING(UNIQ, x, y, ##__VA_ARGS__)

char **strv_reverse(char **l);

bool strv_fnmatch(char *const *patterns, const char *s, int flags);

static inline bool
strv_fnmatch_or_empty(char *const *patterns, const char *s, int flags)
{
	assert(s);
	return strv_isempty(patterns) || strv_fnmatch(patterns, s, flags);
}

char** strv_skip(char **l, size_t n);

#define strv_free_and_replace(a, b)             \
        free_and_replace_full(a, b, strv_free)
