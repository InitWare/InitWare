/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>
#include <errno.h>
#include <stdio.h>

#include "pretty-print.h"
#include "string-util.h"

bool urlify_enabled(void) {
// HACK: We need to decide on this later? Disable for now
#if 0
// #if ENABLE_URLIFY
        static int cached_urlify_enabled = -1;

        if (cached_urlify_enabled < 0) {
                int val;

                val = getenv_bool("SYSTEMD_URLIFY");
                if (val >= 0)
                        cached_urlify_enabled = val;
                else
                        cached_urlify_enabled = colors_enabled();
        }

        return cached_urlify_enabled;
#else
        return 0;
#endif
}

int terminal_urlify(const char *url, const char *text, char **ret) {
        char *n;

        assert(url);

        /* Takes a URL and a pretty string and formats it as clickable link for the terminal. See
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda for details. */

        if (isempty(text))
                text = url;

        if (urlify_enabled())
                n = strjoin("\x1B]8;;", url, "\a", text, "\x1B]8;;\a");
        else
                n = strdup(text);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int terminal_urlify_man(const char *page, const char *section, char **ret) {
        const char *url, *text;

        url = strjoina("man:", page, "(", section, ")");
        text = strjoina(page, "(", section, ") man page");

        return terminal_urlify(url, text, ret);
}
