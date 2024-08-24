/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-argument.h"
#include "parse-util.h"

/* All functions in this file emit warnings. */

int parse_boolean_argument(const char *optname, const char *s, bool *ret) {
        int r;

        /* Returns the result through *ret and the return value. */

        if (s) {
                r = parse_boolean(s);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse boolean argument to %s: %s.", optname, s);

                if (ret)
                        *ret = r;
                return r;
        } else {
                /* s may be NULL. This is controlled by getopt_long() parameters. */
                if (ret)
                        *ret = true;
                return true;
        }
}

int parse_json_argument(const char *s, JsonFormatFlags *ret) {
        assert(s);
        assert(ret);

        if (streq(s, "pretty"))
                *ret = JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO;
        else if (streq(s, "short"))
                *ret = JSON_FORMAT_NEWLINE;
        else if (streq(s, "off"))
                *ret = JSON_FORMAT_OFF;
        else if (streq(s, "help")) {
                puts("pretty\n"
                     "short\n"
                     "off");
                return 0; /* 0 means → we showed a brief help, exit now */
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown argument to --json= switch: %s", s);

        return 1; /* 1 means → properly parsed */
}
