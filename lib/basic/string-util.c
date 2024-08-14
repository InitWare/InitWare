/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here

#include <errno.h>

#include "string-util.h"

char* first_word(const char *s, const char *word) {
        size_t sl, wl;
        const char *p;

        assert(s);
        assert(word);

        /* Checks if the string starts with the specified word, either
         * followed by NUL or by whitespace. Returns a pointer to the
         * NUL or the first character after the whitespace. */

        sl = strlen(s);
        wl = strlen(word);

        if (sl < wl)
                return NULL;

        if (wl == 0)
                return (char*) s;

        if (memcmp(s, word, wl) != 0)
                return NULL;

        p = s + wl;
        if (*p == 0)
                return (char*) p;

        if (!strchr(WHITESPACE, *p))
                return NULL;

        p += strspn(p, WHITESPACE);
        return (char*) p;
}

char *strnappend(const char *s, const char *suffix, size_t b) {
        size_t a;
        char *r;

        if (!s && !suffix)
                return strdup("");

        if (!s)
                return strndup(suffix, b);

        if (!suffix)
                return strdup(s);

        assert(s);
        assert(suffix);

        a = strlen(s);
        if (b > SIZE_MAX - a)
                return NULL;

        r = new(char, a+b+1);
        if (!r)
                return NULL;

        memcpy(r, s, a);
        memcpy(r+a, suffix, b);
        r[a+b] = 0;

        return r;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string,
         * possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);

        return 1;
}

int free_and_strndup(char **p, const char *s, size_t l) {
        char *t;

        assert(p);
        assert(s || l == 0);

        /* Replaces a string pointer with a strndup()ed new string,
         * freeing the old one. */

        if (!*p && !s)
                return 0;

        if (*p && s && strneq(*p, s, l) && (l > strlen(*p) || (*p)[l] == '\0'))
                return 0;

        if (s) {
                t = strndup(s, l);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);
        return 1;
}

int strdup_to_full(char **ret, const char *src) {
        if (!src) {
                if (ret)
                        *ret = NULL;

                return 0;
        } else {
                if (ret) {
                        char *t = strdup(src);
                        if (!t)
                                return -ENOMEM;
                        *ret = t;
                }

                return 1;
        }
};