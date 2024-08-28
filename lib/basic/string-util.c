/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here

#include <errno.h>

#include "escape.h"
#include "glyph-util.h"
#include "gunicode.h"
#include "string-util.h"
#include "utf8.h"

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

char *strdupspn(const char *a, const char *accept) {
        if (isempty(a) || isempty(accept))
                return strdup("");

        return strndup(a, strspn(a, accept));
}

char *strdupcspn(const char *a, const char *reject) {
        if (isempty(a))
                return strdup("");
        if (isempty(reject))
                return strdup(a);

        return strndup(a, strcspn(a, reject));
}

char *strreplace(const char *text, const char *old_string, const char *new_string) {
        size_t l, old_len, new_len;
        char *t, *ret = NULL;
        const char *f;

        assert(old_string);
        assert(new_string);

        if (!text)
                return NULL;

        old_len = strlen(old_string);
        new_len = strlen(new_string);

        l = strlen(text);
        if (!GREEDY_REALLOC(ret, l+1))
                return NULL;

        f = text;
        t = ret;
        while (*f) {
                size_t d, nl;

                if (!startswith(f, old_string)) {
                        *(t++) = *(f++);
                        continue;
                }

                d = t - ret;
                nl = l - old_len + new_len;

                if (!GREEDY_REALLOC(ret, nl + 1))
                        return mfree(ret);

                l = nl;
                t = ret + d;

                t = stpcpy(t, new_string);
                f += old_len;
        }

        *t = 0;
        return ret;
}

char *find_line_startswith(const char *haystack, const char *needle) {
        char *p;

        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that starts with the specified string. Returns a pointer to the
         * first character after it */

        p = strstr(haystack, needle);
        if (!p)
                return NULL;

        if (p > haystack)
                while (p[-1] != '\n') {
                        p = strstr(p + 1, needle);
                        if (!p)
                                return NULL;
                }

        return p + strlen(needle);
}

static int write_ellipsis(char *buf, bool unicode) {
        const char *s = special_glyph_full(SPECIAL_GLYPH_ELLIPSIS, unicode);
        assert(strlen(s) == 3);
        memcpy(buf, s, 3);
        return 3;
}

static size_t ansi_sequence_length(const char *s, size_t len) {
        assert(s);

        if (len < 2)
                return 0;

        if (s[0] != 0x1B)  /* ASCII 27, aka ESC, aka Ctrl-[ */
                return 0;  /* Not the start of a sequence */

        if (s[1] == 0x5B) { /* [, start of CSI sequence */
                size_t i = 2;

                if (i == len)
                        return 0;

                while (s[i] >= 0x30 && s[i] <= 0x3F) /* Parameter bytes */
                        if (++i == len)
                                return 0;
                while (s[i] >= 0x20 && s[i] <= 0x2F) /* Intermediate bytes */
                        if (++i == len)
                                return 0;
                if (s[i] >= 0x40 && s[i] <= 0x7E) /* Final byte */
                        return i + 1;
                return 0;  /* Bad sequence */

        } else if (s[1] >= 0x40 && s[1] <= 0x5F) /* other non-CSI Fe sequence */
                return 2;

        return 0;  /* Bad escape? */
}

static bool string_has_ansi_sequence(const char *s, size_t len) {
        const char *t = s;

        while ((t = memchr(s, 0x1B, len - (t - s))))
                if (ansi_sequence_length(t, len - (t - s)) > 0)
                        return true;
        return false;
}

static size_t previous_ansi_sequence(const char *s, size_t length, const char **ret_where) {
        /* Locate the previous ANSI sequence and save its start in *ret_where and return length. */

        for (size_t i = length - 2; i > 0; i--) {  /* -2 because at least two bytes are needed */
                size_t slen = ansi_sequence_length(s + (i - 1), length - (i - 1));
                if (slen == 0)
                        continue;

                *ret_where = s + (i - 1);
                return slen;
        }

        *ret_where = NULL;
        return 0;
}

static char *ascii_ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, need_space, suffix_len;
        char *t;

        assert(s);
        assert(percent <= 100);
        assert(new_length != SIZE_MAX);

        if (old_length <= new_length)
                return strndup(s, old_length);

        /* Special case short ellipsations */
        switch (new_length) {

        case 0:
                return strdup("");

        case 1:
                if (is_locale_utf8())
                        return strdup("…");
                else
                        return strdup(".");

        case 2:
                if (!is_locale_utf8())
                        return strdup("..");

                break;

        default:
                break;
        }

        /* Calculate how much space the ellipsis will take up. If we are in UTF-8 mode we only need space for one
         * character ("…"), otherwise for three characters ("..."). Note that in both cases we need 3 bytes of storage,
         * either for the UTF-8 encoded character or for three ASCII characters. */
        need_space = is_locale_utf8() ? 1 : 3;

        t = new(char, new_length+3);
        if (!t)
                return NULL;

        assert(new_length >= need_space);

        x = ((new_length - need_space) * percent + 50) / 100;
        assert(x <= new_length - need_space);

        write_ellipsis(mempcpy(t, s, x), /* unicode = */ false);
        suffix_len = new_length - x - need_space;
        memcpy(t + x + 3, s + old_length - suffix_len, suffix_len);
        *(t + x + 3 + suffix_len) = '\0';

        return t;
}

char *ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, k, len, len2;
        const char *i, *j;
        int r;

        /* Note that 'old_length' refers to bytes in the string, while 'new_length' refers to character cells taken up
         * on screen. This distinction doesn't matter for ASCII strings, but it does matter for non-ASCII UTF-8
         * strings.
         *
         * Ellipsation is done in a locale-dependent way:
         * 1. If the string passed in is fully ASCII and the current locale is not UTF-8, three dots are used ("...")
         * 2. Otherwise, a unicode ellipsis is used ("…")
         *
         * In other words: you'll get a unicode ellipsis as soon as either the string contains non-ASCII characters or
         * the current locale is UTF-8.
         */

        assert(s);
        assert(percent <= 100);

        if (new_length == SIZE_MAX)
                return strndup(s, old_length);

        if (new_length == 0)
                return strdup("");

        bool has_ansi_seq = string_has_ansi_sequence(s, old_length);

        /* If no multibyte characters or ANSI sequences, use ascii_ellipsize_mem for speed */
        if (!has_ansi_seq && ascii_is_valid_n(s, old_length))
                return ascii_ellipsize_mem(s, old_length, new_length, percent);

        x = (new_length - 1) * percent / 100;
        assert(x <= new_length - 1);

        k = 0;
        for (i = s; i < s + old_length; ) {
                size_t slen = has_ansi_seq ? ansi_sequence_length(i, old_length - (i - s)) : 0;
                if (slen > 0) {
                        i += slen;
                        continue;  /* ANSI sequences don't take up any space in output */
                }

                char32_t c;
                r = utf8_encoded_to_unichar(i, &c);
                if (r < 0)
                        return NULL;

                int w = unichar_iswide(c) ? 2 : 1;
                if (k + w > x)
                        break;

                k += w;
                i += r;
        }

        const char *ansi_start = s + old_length;
        size_t ansi_len = 0;

        for (const char *t = j = s + old_length; t > i && k < new_length; ) {
                char32_t c;
                int w;
                const char *tt;

                if (has_ansi_seq && ansi_start >= t)
                        /* Figure out the previous ANSI sequence, if any */
                        ansi_len = previous_ansi_sequence(s, t - s, &ansi_start);

                /* If the sequence extends all the way to the current position, skip it. */
                if (has_ansi_seq && ansi_len > 0 && ansi_start + ansi_len == t) {
                        t = ansi_start;
                        continue;
                }

                tt = utf8_prev_char(t);
                r = utf8_encoded_to_unichar(tt, &c);
                if (r < 0)
                        return NULL;

                w = unichar_iswide(c) ? 2 : 1;
                if (k + w > new_length)
                        break;

                k += w;
                j = t = tt;  /* j should always point to the first "real" character */
        }

        /* We don't actually need to ellipsize */
        if (i >= j)
                return memdup_suffix0(s, old_length);

        if (k >= new_length) {
                /* Make space for ellipsis, if required and possible. We know that the edge character is not
                 * part of an ANSI sequence (because then we'd skip it). If the last character we looked at
                 * was wide, we don't need to make space. */
                if (j < s + old_length)
                        j = utf8_next_char(j);
                else if (i > s)
                        i = utf8_prev_char(i);
        }

        len = i - s;
        len2 = s + old_length - j;

        /* If we have ANSI, allow the same length as the source string + ellipsis. It'd be too involved to
         * figure out what exact space is needed. Strings with ANSI sequences are most likely to be fairly
         * short anyway. */
        size_t alloc_len = has_ansi_seq ? old_length + 3 + 1 : len + 3 + len2 + 1;

        char *e = new(char, alloc_len);
        if (!e)
                return NULL;

        memcpy_safe(e, s, len);
        write_ellipsis(e + len, /* unicode = */ true);

        char *dst = e + len + 3;

        if (has_ansi_seq)
                /* Copy over any ANSI sequences in full */
                for (const char *p = s + len; p < j; ) {
                        size_t slen = ansi_sequence_length(p, j - p);
                        if (slen > 0) {
                                dst = mempcpy(dst, p, slen);
                                p += slen;
                        } else
                                p = utf8_next_char(p);
                }

        memcpy_safe(dst, j, len2);
        dst[len2] = '\0';

        return e;
}

char *cellescape(char *buf, size_t len, const char *s) {
        /* Escape and ellipsize s into buffer buf of size len. Only non-control ASCII
         * characters are copied as they are, everything else is escaped. The result
         * is different then if escaping and ellipsization was performed in two
         * separate steps, because each sequence is either stored in full or skipped.
         *
         * This function should be used for logging about strings which expected to
         * be plain ASCII in a safe way.
         *
         * An ellipsis will be used if s is too long. It was always placed at the
         * very end.
         */

        size_t i = 0, last_char_width[4] = {}, k = 0;

        assert(buf);
        assert(len > 0); /* at least a terminating NUL */
        assert(s);

        for (;;) {
                char four[4];
                int w;

                if (*s == 0) /* terminating NUL detected? then we are done! */
                        goto done;

                w = cescape_char(*s, four);
                if (i + w + 1 > len) /* This character doesn't fit into the buffer anymore? In that case let's
                                      * ellipsize at the previous location */
                        break;

                /* OK, there was space, let's add this escaped character to the buffer */
                memcpy(buf + i, four, w);
                i += w;

                /* And remember its width in the ring buffer */
                last_char_width[k] = w;
                k = (k + 1) % 4;

                s++;
        }

        /* Ellipsation is necessary. This means we might need to truncate the string again to make space for 4
         * characters ideally, but the buffer is shorter than that in the first place take what we can get */
        for (size_t j = 0; j < ELEMENTSOF(last_char_width); j++) {

                if (i + 4 <= len) /* nice, we reached our space goal */
                        break;

                k = k == 0 ? 3 : k - 1;
                if (last_char_width[k] == 0) /* bummer, we reached the beginning of the strings */
                        break;

                assert(i >= last_char_width[k]);
                i -= last_char_width[k];
        }

        if (i + 4 <= len) /* yay, enough space */
                i += write_ellipsis(buf + i, /* unicode = */ false);
        else if (i + 3 <= len) { /* only space for ".." */
                buf[i++] = '.';
                buf[i++] = '.';
        } else if (i + 2 <= len) /* only space for a single "." */
                buf[i++] = '.';
        else
                assert(i + 1 <= len);

done:
        buf[i] = '\0';
        return buf;
}

int string_truncate_lines(const char *s, size_t n_lines, char **ret) {
        const char *p = s, *e = s;
        bool truncation_applied = false;
        char *copy;
        size_t n = 0;

        assert(s);

        /* Truncate after the specified number of lines. Returns > 0 if a truncation was applied or == 0 if
         * there were fewer lines in the string anyway. Trailing newlines on input are ignored, and not
         * generated either. */

        for (;;) {
                size_t k;

                k = strcspn(p, "\n");

                if (p[k] == 0) {
                        if (k == 0) /* final empty line */
                                break;

                        if (n >= n_lines) /* above threshold */
                                break;

                        e = p + k; /* last line to include */
                        break;
                }

                assert(p[k] == '\n');

                if (n >= n_lines)
                        break;

                if (k > 0)
                        e = p + k;

                p += k + 1;
                n++;
        }

        /* e points after the last character we want to keep */
        if (isempty(e))
                copy = strdup(s);
        else {
                if (!in_charset(e, "\n")) /* We only consider things truncated if we remove something that
                                           * isn't a new-line or a series of them */
                        truncation_applied = true;

                copy = strndup(s, e - s);
        }
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return truncation_applied;
}

int string_extract_line(const char *s, size_t i, char **ret) {
        const char *p = s;
        size_t c = 0;

        /* Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
         * and == 0 if we are looking at the last line or already beyond the last line. As special
         * optimization, if the first line is requested and the string only consists of one line we return
         * NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
         * common case. */

        for (;;) {
                const char *q;

                q = strchr(p, '\n');
                if (i == c) {
                        /* The line we are looking for! */

                        if (q) {
                                char *m;

                                m = strndup(p, q - p);
                                if (!m)
                                        return -ENOMEM;

                                *ret = m;
                                return !isempty(q + 1); /* More coming? */
                        } else
                                /* Tell the caller to use the input string if equal */
                                return strdup_to(ret, p != s ? p : NULL);
                }

                if (!q)
                        /* No more lines, return empty line */
                        return strdup_to(ret, "");

                p = q + 1;
                c++;
        }
}

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret) {
        char *b;

        assert(s || n == 0);
        assert(mode >= 0);
        assert(mode < _MAKE_CSTRING_MODE_MAX);

        /* Converts a sized character buffer into a NUL-terminated NUL string, refusing if there are embedded
         * NUL bytes. Whether to expect a trailing NUL byte can be specified via 'mode' */

        if (n == 0) {
                if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = new0(char, 1);
        } else {
                const char *nul;

                nul = memchr(s, 0, n);
                if (nul) {
                        if (nul < s + n - 1 || /* embedded NUL? */
                            mode == MAKE_CSTRING_REFUSE_TRAILING_NUL)
                                return -EINVAL;

                        n--;
                } else if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = memdup_suffix0(s, n);
        }
        if (!b)
                return -ENOMEM;

        *ret = b;
        return 0;
}

char *delete_trailing_chars(char *s, const char *bad) {
        char *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (char *p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}
