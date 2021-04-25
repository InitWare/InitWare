
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

#endif
