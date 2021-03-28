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
/**
 * PTGroups using Kernel Queues.
 */

#ifndef KQPROC_H_
#define KQPROC_H_

#include "ptgroup.h"

typedef struct Manager Manager;

/** setup the Kernel Queue and watch */
int manager_setup_kqproc_watch(Manager *m);

/** there has been activity on the Kernel Queue */
void manager_kqproc_event(Manager *m);


#endif