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

#include "ev.h"

#include "macro.h"

#ifndef EV_UTIL_H_
#define EV_UTIL_H_

/* Clear an I/O watch. */
#define ev_io_zero(watch)       \
        do {                    \
                zero(watch);   \
                watch->fd = -1; \
        } while (0);

/* Clear a timer watch. */
#define ev_timer_zero(watch) zero(watch)

#define ev_periodic_zero(watch) zero(watch)

#endif
