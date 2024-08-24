/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-file.h"
#include "escape.h"
#include "fileio.h"
#include "string-util.h"
#include "utf8.h"

typedef int (*push_env_func_t)(
                const char *filename,
                unsigned line,
                const char *key,
                char *value,
                void *userdata);

static int parse_env_file_internal(
                FILE *f,
                const char *fname,
                push_env_func_t push,
                void *userdata) {

        size_t n_key = 0, n_value = 0, last_value_whitespace = SIZE_MAX, last_key_whitespace = SIZE_MAX;
        _cleanup_free_ char *contents = NULL, *key = NULL, *value = NULL;
        unsigned line = 1;
        int r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                VALUE_ESCAPE,
                SINGLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE_ESCAPE,
                COMMENT,
                COMMENT_ESCAPE
        } state = PRE_KEY;

        assert(f || fname);
        assert(push);

        if (f)
                r = read_full_stream(f, &contents, NULL);
        else
                r = read_full_file(fname, &contents, NULL);
        if (r < 0)
                return r;

        for (char *p = contents; *p; p++) {
                char c = *p;

                switch (state) {

                case PRE_KEY:
                        if (strchr(COMMENTS, c))
                                state = COMMENT;
                        else if (!strchr(WHITESPACE, c)) {
                                state = KEY;
                                last_key_whitespace = SIZE_MAX;

                                if (!GREEDY_REALLOC(key, n_key+2))
                                        return -ENOMEM;

                                key[n_key++] = c;
                        }
                        break;

                case KEY:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                                n_key = 0;
                        } else if (c == '=') {
                                state = PRE_VALUE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_key_whitespace = SIZE_MAX;
                                else if (last_key_whitespace == SIZE_MAX)
                                         last_key_whitespace = n_key;

                                if (!GREEDY_REALLOC(key, n_key+2))
                                        return -ENOMEM;

                                key[n_key++] = c;
                        }

                        break;

                case PRE_VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        return r;

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\'')
                                state = SINGLE_QUOTE_VALUE;
                        else if (c == '"')
                                state = DOUBLE_QUOTE_VALUE;
                        else if (c == '\\')
                                state = VALUE_ESCAPE;
                        else if (!strchr(WHITESPACE, c)) {
                                state = VALUE;

                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;

                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* Chomp off trailing whitespace from value */
                                if (last_value_whitespace != SIZE_MAX)
                                        value[last_value_whitespace] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        return r;

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\\') {
                                state = VALUE_ESCAPE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_value_whitespace = SIZE_MAX;
                                else if (last_value_whitespace == SIZE_MAX)
                                        last_value_whitespace = n_value;

                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE_ESCAPE:
                        state = VALUE;

                        if (!strchr(NEWLINE, c)) {
                                /* Escaped newlines we eat up entirely */
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }
                        break;

                case SINGLE_QUOTE_VALUE:
                        if (c == '\'')
                                state = PRE_VALUE;
                        else {
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE:
                        if (c == '"')
                                state = PRE_VALUE;
                        else if (c == '\\')
                                state = DOUBLE_QUOTE_VALUE_ESCAPE;
                        else {
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE_ESCAPE:
                        state = DOUBLE_QUOTE_VALUE;

                        if (strchr(SHELL_NEED_ESCAPE, c)) {
                                /* If this is a char that needs escaping, just unescape it. */
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;
                                value[n_value++] = c;
                        } else if (c != '\n') {
                                /* If other char than what needs escaping, keep the "\" in place, like the
                                 * real shell does. */
                                if (!GREEDY_REALLOC(value, n_value+3))
                                        return -ENOMEM;
                                value[n_value++] = '\\';
                                value[n_value++] = c;
                        }

                        /* Escaped newlines (aka "continuation lines") are eaten up entirely */
                        break;

                case COMMENT:
                        if (c == '\\')
                                state = COMMENT_ESCAPE;
                        else if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                        }
                        break;

                case COMMENT_ESCAPE:
                        log_debug("The line which doesn't begin with \";\" or \"#\", but follows a comment" \
                                  " line trailing with escape is now treated as a non comment line since v254.");
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                        } else
                                state = COMMENT;
                        break;
                }
        }

        if (IN_SET(state,
                   PRE_VALUE,
                   VALUE,
                   VALUE_ESCAPE,
                   SINGLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE_ESCAPE)) {

                key[n_key] = 0;

                if (value)
                        value[n_value] = 0;

                if (state == VALUE)
                        if (last_value_whitespace != SIZE_MAX)
                                value[last_value_whitespace] = 0;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != SIZE_MAX)
                        key[last_key_whitespace] = 0;

                r = push(fname, line, key, value, userdata);
                if (r < 0)
                        return r;

                value = NULL;
        }

        return 0;
}

static int check_utf8ness_and_warn(
                const char *filename, unsigned line,
                const char *key, char *value) {

        assert(key);

        if (!utf8_is_valid(key)) {
                _cleanup_free_ char *p = NULL;

                p = utf8_escape_invalid(key);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: invalid UTF-8 in key '%s', ignoring.",
                                       strna(filename), line, p);
        }

        if (value && !utf8_is_valid(value)) {
                _cleanup_free_ char *p = NULL;

                p = utf8_escape_invalid(value);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
                                       strna(filename), line, key, p);
        }

        return 0;
}

static int parse_env_file_push(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        const char *k;
        va_list aq, *ap = userdata;
        int r;

        assert(key);

        r = check_utf8ness_and_warn(filename, line, key, value);
        if (r < 0)
                return r;

        va_copy(aq, *ap);

        while ((k = va_arg(aq, const char *))) {
                char **v;

                v = va_arg(aq, char **);

                if (streq(key, k)) {
                        va_end(aq);
                        free_and_replace(*v, value);

                        return 1;
                }
        }

        va_end(aq);
        free(value);

        return 0;
}

int parse_env_file_fdv(int fd, const char *fname, va_list ap) {
        _cleanup_fclose_ FILE *f = NULL;
        va_list aq;
        int r;

        assert(fd >= 0);

        r = fdopen_independent(fd, "re", &f);
        if (r < 0)
                return r;

        va_copy(aq, ap);
        r = parse_env_file_internal(f, fname, parse_env_file_push, &aq);
        va_end(aq);
        return r;
}
