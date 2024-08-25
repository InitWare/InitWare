/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fileio.h"
#include "ordered-set.h"
#include "strv.h"

int ordered_set_consume(OrderedSet *s, void *p) {
        int r;

        r = ordered_set_put(s, p);
        if (r <= 0)
                free(p);

        return r;
}
