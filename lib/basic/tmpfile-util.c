/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "fs-util.h"
#include "path-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

int mkdtemp_malloc(const char *template, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(ret);

        if (template)
                p = strdup(template);
        else {
                const char *tmp;

                r = tmp_dir(&tmp);
                if (r < 0)
                        return r;

                p = path_join(tmp, "XXXXXX");
        }
        if (!p)
                return -ENOMEM;

        if (!mkdtemp(p))
                return -errno;

        *ret = TAKE_PTR(p);
        return 0;
}
