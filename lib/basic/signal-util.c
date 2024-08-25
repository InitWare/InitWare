/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>

#include "errno-util.h"
#include "macro.h"
#include "signal-util.h"

int signal_is_blocked(int sig) {
        sigset_t ss;
        int r;

        r = pthread_sigmask(SIG_SETMASK, NULL, &ss);
        if (r != 0)
                return -r;

        return RET_NERRNO(sigismember(&ss, sig));
}
