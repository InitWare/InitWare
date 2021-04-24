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

#ifndef PTGROUP_SHOW_H
#define PTGROUP_SHOW_H

#include <sys/types.h>

#include "cJSON.h"
#include "logs-show.h"

int show_ptgroup(cJSON *ptgroup, const char *prefix, unsigned columns, bool kernel_threads, OutputFlags flags);
int show_ptgroup_and_extra(
        cJSON *ptgroup,
        const char *prefix,
        unsigned n_columns,
        bool kernel_threads,
        const pid_t extra_pids[],
        unsigned n_extra_pids,
        OutputFlags flags);

#endif
