/*******************************************************************

    LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

    (c) 2021 David Mackay
        All rights reserved.
*********************************************************************/
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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "cjson-util.h"
#include "macro.h"
#include "path-util.h"
#include "ptgroup-show.h"
#include "util.h"

static int compare(const void *a, const void *b) {
        const pid_t *p = a, *q = b;

        if (*p < *q)
                return -1;
        if (*p > *q)
                return 1;
        return 0;
}

static void show_pid_array(
        int pids[],
        unsigned n_pids,
        const char *prefix,
        unsigned n_columns,
        bool extra,
        bool more,
        bool kernel_threads,
        OutputFlags flags) {
        unsigned i, m, pid_width;
        pid_t biggest = 0;

        /* Filter duplicates */
        m = 0;
        for (i = 0; i < n_pids; i++) {
                unsigned j;

                if (pids[i] > biggest)
                        biggest = pids[i];

                for (j = i + 1; j < n_pids; j++)
                        if (pids[i] == pids[j])
                                break;

                if (j >= n_pids)
                        pids[m++] = pids[i];
        }
        n_pids = m;
        pid_width = DECIMAL_STR_WIDTH(biggest);

        /* And sort */
        qsort_safe(pids, n_pids, sizeof(pid_t), compare);

        if (flags & OUTPUT_FULL_WIDTH)
                n_columns = 0;
        else {
                if (n_columns > pid_width + 2)
                        n_columns -= pid_width + 2;
                else
                        n_columns = 20;
        }
        for (i = 0; i < n_pids; i++) {
                char *t = NULL;

                get_process_cmdline(pids[i], n_columns, true, &t);

                printf("%s%s%*lu %s\n",
                       prefix,
                       draw_special_char(
                               extra ? DRAW_TRIANGULAR_BULLET :
                                       ((more || i < n_pids - 1) ? DRAW_TREE_BRANCH : DRAW_TREE_RIGHT)),
                       pid_width,
                       (unsigned long) pids[i],
                       strna(t));

                free(t);
        }
}

#define is_kernel_thread(...) 0

/**
 * Print out the processes within a PTGroup.
 */
static int show_ptgroup_one(
        cJSON *ptgroup, const char *prefix, unsigned n_columns, bool more, bool kernel_threads, OutputFlags flags) {
        char *fn;
        size_t n = 0, n_allocated = 0;
        _cleanup_free_ pid_t *pids = NULL;
        char *p = NULL;
        pid_t pid;
        cJSON *oPid = NULL;

        cJSON_ArrayForEach(oPid, cJSON_GetObjectItem(ptgroup, "processes")) {

                pid = cJSON_GetNumberValue(oPid);

                if (!kernel_threads && is_kernel_thread(pid) > 0)
                        continue;

                if (n >= n_allocated) {
                        pid_t *npids;

                        n_allocated = MAX(16U, n * 2U);

                        npids = realloc(pids, sizeof(pid_t) * n_allocated);
                        if (!npids)
                                return -ENOMEM;

                        pids = npids;
                }

                assert(n < n_allocated);
                pids[n++] = pid;
        }

        if (n > 0)
                show_pid_array(pids, n, prefix, n_columns, false, more, kernel_threads, flags);

        return 0;
}

int show_ptgroup(cJSON *ptgroup, const char *prefix, unsigned n_columns, bool kernel_threads, OutputFlags flags) {
        _cleanup_free_ char *fn = NULL, *p1 = NULL, *p2 = NULL;
        char *gn = NULL;
	bool shown_pids = false;
	cJSON *oGroup;
        cJSON *last = NULL;

        assert(ptgroup);

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";


        cJSON_ArrayForEach(oGroup, cJSON_GetObjectItem(ptgroup, "groups")) {

                /* FIXME: It's trying to not show empty CGroups or what?
                if (!(flags & OUTPUT_SHOW_ALL) && cg_is_empty_recursive(NULL, k, false) > 0)
                        continue;*/

                if (!shown_pids) {
                        show_ptgroup_one(ptgroup, prefix, n_columns, true, kernel_threads, flags);
                        shown_pids = true;
                }


                if (last) {
                        printf("%s%s%s\n",
                               prefix,
                               draw_special_char(DRAW_TREE_BRANCH),
                               cJSON_GetObjectItem(last, "name")->valuestring);

                        if (!p1) {
                                p1 = strappend(prefix, draw_special_char(DRAW_TREE_VERT));
                                if (!p1)
                                        return -ENOMEM;
                        }

                        show_ptgroup(last, p1, n_columns - 2, kernel_threads, flags);
                        free(last);
                }

                last = oGroup;
        }

	if (!shown_pids)
                show_ptgroup_one(ptgroup, prefix, n_columns, !!last, kernel_threads, flags);

        if (last) {
                printf("%s%s%s\n",
                       prefix,
                       draw_special_char(DRAW_TREE_RIGHT),
                       cJSON_GetObjectItem(last, "name")->valuestring);

                if (!p2) {
                        p2 = strappend(prefix, "  ");
                        if (!p2)
                                return -ENOMEM;
                }

                show_ptgroup(last, p2, n_columns - 2, kernel_threads, flags);
        }

        return 0;
}


static int show_extra_pids(
        cJSON *ptgroup,
        const char *prefix,
        unsigned n_columns,
        const pid_t pids[],
        unsigned n_pids,
        OutputFlags flags) {
        _cleanup_free_ pid_t *copy = NULL;
        unsigned i, j;
        int r;

        assert(ptgroup);

        if (n_pids <= 0)
                return 0;

        if (n_columns <= 0)
                n_columns = columns();

        /*        prefix = strempty(prefix);

                copy = new(pid_t, n_pids);
                if (!copy)
                        return -ENOMEM;

                for (i = 0, j = 0; i < n_pids; i++) {
                        _cleanup_free_ char *k = NULL;

                        r = cg_pid_get_path(controller, pids[i], &k);
                        if (r < 0)
                                return r;

                        if (path_startswith(k, path))
                                continue;

                        copy[j++] = pids[i];
                }

                show_pid_array(copy, j, prefix, n_columns, true, false, false, flags);*/

        return 0;
}

int show_ptgroup_and_extra(
        cJSON *ptgroup,
        const char *prefix,
        unsigned n_columns,
        bool kernel_threads,
        const pid_t extra_pids[],
        unsigned n_extra_pids,
        OutputFlags flags) {
        int r;

        assert(ptgroup);
        r = show_ptgroup(ptgroup, prefix, n_columns, kernel_threads, flags);
        if (r < 0)
                return r;

        return show_extra_pids(ptgroup, prefix, n_columns, extra_pids, n_extra_pids, flags);
}
