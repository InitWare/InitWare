/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"

int parse_boolean(const char *v) {
        if (!v)
                return -EINVAL;

        if (STRCASE_IN_SET(v,
                           "1",
                           "yes",
                           "y",
                           "true",
                           "t",
                           "on"))
                return 1;

        if (STRCASE_IN_SET(v,
                           "0",
                           "no",
                           "n",
                           "false",
                           "f",
                           "off"))
                return 0;

        return -EINVAL;
}

int parse_tristate_full(const char *v, const char *third, int *ret) {
        int r;

        if (isempty(v) || streq_ptr(v, third)) { /* Empty string is always taken as the third/invalid/auto state */
                if (ret)
                        *ret = -1;
        } else {
                r = parse_boolean(v);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = r;
        }

        return 0;
}

int parse_pid(const char *s, pid_t* ret_pid) {
        unsigned long ul = 0;
        pid_t pid;
        int r;

        assert(s);

        r = safe_atolu(s, &ul);
        if (r < 0)
                return r;

        pid = (pid_t) ul;

        if ((unsigned long) pid != ul)
                return -ERANGE;

        if (!pid_is_valid(pid))
                return -ERANGE;

        if (ret_pid)
                *ret_pid = pid;
        return 0;
}
