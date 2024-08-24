/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"

#include "macro.h"

// HACK: We don't do SD_BOOT
// #if SD_BOOT
#if 0
#  define strlen strlen16
#  define strcmp strcmp16
#  define strncmp strncmp16
#  define strcasecmp strcasecmp16
#  define strncasecmp strncasecmp16
#  define STR_C(str)       (L ## str)
typedef char16_t sd_char;
#else
#  define STR_C(str)       (str)
typedef char sd_char;
#endif

/* What is interpreted as whitespace? */
#define WHITESPACE          " \t\n\r"
#define NEWLINE             "\n\r"
#define QUOTES              "\"\'"
#define COMMENTS            "#;"
#define GLOB_CHARS          "*?["
#define DIGITS              "0123456789"
#define LOWERCASE_LETTERS   "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS             LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL      LETTERS DIGITS
#define HEXDIGITS           DIGITS "abcdefABCDEF"
#define LOWERCASE_HEXDIGITS DIGITS "abcdef"
#define URI_RESERVED        ":/?#[]@!$&'()*+;="         /* [RFC3986] */
#define URI_UNRESERVED      ALPHANUMERICAL "-._~"       /* [RFC3986] */
#define URI_VALID           URI_RESERVED URI_UNRESERVED /* [RFC3986] */

static inline char* strstr_ptr(const char *haystack, const char *needle) {
        if (!haystack || !needle)
                return NULL;
        return strstr(haystack, needle);
}

static inline char *strstrafter(const char *haystack, const char *needle) {
        char *p;

        /* Returns NULL if not found, or pointer to first character after needle if found */

        p = strstr_ptr(haystack, needle);
        if (!p)
                return NULL;

        return p + strlen(needle);
}

static inline const char* strnull(const char *s) {
        return s ?: "(null)";
}

static inline const char *strna(const char *s) {
        return s ?: "n/a";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* plus_minus(bool b) {
        return b ? "+" : "-";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

static inline const char* enable_disable(bool b) {
        return b ? "enable" : "disable";
}

static inline const char* enabled_disabled(bool b) {
        return b ? "enabled" : "disabled";
}

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

static inline int strcmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcmp(a, b);

        return CMP(a, b);
}

static inline int strcasecmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcasecmp(a, b);

        return CMP(a, b);
}

static inline bool streq_ptr(const sd_char *a, const sd_char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline bool strcaseeq_ptr(const sd_char *a, const sd_char *b) {
        return strcasecmp_ptr(a, b) == 0;
}

static inline bool ascii_isdigit(sd_char a) {
        /* A pure ASCII, locale independent version of isdigit() */
        return a >= '0' && a <= '9';
}

static inline bool ascii_ishex(sd_char a) {
        return ascii_isdigit(a) || (a >= 'a' && a <= 'f') || (a >= 'A' && a <= 'F');
}

static inline bool ascii_isalpha(sd_char a) {
        /* A pure ASCII, locale independent version of isalpha() */
        return (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z');
}

static inline size_t strlen_ptr(const sd_char *s) {
        if (!s)
                return 0;

        return strlen(s);
}

static inline bool isempty(const sd_char *a) {
        return !a || a[0] == '\0';
}

static inline const sd_char *strempty(const sd_char *s) {
        return s ?: STR_C("");
}

static inline const sd_char *yes_no(bool b) {
        return b ? STR_C("yes") : STR_C("no");
}

/* This macro's return pointer will have the "const" qualifier set or unset the same way as the input
 * pointer. */
#define empty_to_null(p)                                \
        ({                                              \
                const char *_p = (p);                   \
                (typeof(p)) (isempty(_p) ? NULL : _p);  \
        })

static inline const char *empty_to_na(const char *p) {
        return isempty(p) ? "n/a" : p;
}

static inline const char *empty_to_dash(const char *str) {
        return isempty(str) ? "-" : str;
}

static inline bool empty_or_dash(const char *str) {
        return !str ||
                str[0] == 0 ||
                (str[0] == '-' && str[1] == 0);
}

static inline const char *empty_or_dash_to_null(const char *p) {
        return empty_or_dash(p) ? NULL : p;
}
#define empty_or_dash_to_null(p)                                \
        ({                                                      \
                const char *_p = (p);                           \
                (typeof(p)) (empty_or_dash(_p) ? NULL : _p);    \
        })

char *first_word(const char *s, const char *word) _pure_;

char *strnappend(const char *s, const char *suffix, size_t length);

#define _STRV_FOREACH(s, l, i)                                          \
        for (typeof(*(l)) *s, *i = (l); (s = i) && *i; i++)

#define STRV_FOREACH(s, l)                      \
        _STRV_FOREACH(s, l, UNIQ_T(i, UNIQ))

static inline char* skip_leading_chars(const char *s, const char *bad) {
        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        return (char*) s + strspn(s, bad);
}

int free_and_strdup(char **p, const char *s);
static inline int free_and_strdup_warn(char **p, const char *s) {
        int r;

        r = free_and_strdup(p, s);
        if (r < 0)
                return log_oom();
        return r;
}
int free_and_strndup(char **p, const char *s, size_t l);

char *strreplace(const char *text, const char *old_string, const char *new_string);

int strdup_to_full(char **ret, const char *src);
static inline int strdup_to(char **ret, const char *src) {
        int r = strdup_to_full(ASSERT_PTR(ret), src);
        return r < 0 ? r : 0;  /* Suppress return value of 1. */
}

/* Like startswith(), but operates on arbitrary memory blocks */
static inline void *memory_startswith(const void *p, size_t sz, const sd_char *token) {
        assert(token);

        size_t n = strlen(token) * sizeof(sd_char);
        if (sz < n)
                return NULL;

        assert(p);

        if (memcmp(p, token, n) != 0)
                return NULL;

        return (uint8_t*) p + n;
}

int string_contains_word_strv(const char *string, const char *separators, char * const *words, const char **ret_word);
static inline int string_contains_word(const char *string, const char *separators, const char *word) {
        return string_contains_word_strv(string, separators, STRV_MAKE(word), NULL);
}

typedef enum MakeCStringMode {
        MAKE_CSTRING_REFUSE_TRAILING_NUL,
        MAKE_CSTRING_ALLOW_TRAILING_NUL,
        MAKE_CSTRING_REQUIRE_TRAILING_NUL,
        _MAKE_CSTRING_MODE_MAX,
        _MAKE_CSTRING_MODE_INVALID = -1,
} MakeCStringMode;

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret);

char *strdupspn(const char *a, const char *accept);
char *strdupcspn(const char *a, const char *reject);

char *find_line_startswith(const char *haystack, const char *needle);
