/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "svc-config.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#endif

#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "parse-util.h"
#include "process-util.h"
#include "util.h"
#include "terminal-util.h"

static volatile int cached_on_dev_null = -1;
static volatile int cached_color_mode = _COLOR_INVALID;
static volatile int cached_underline_enabled = -1;

static bool on_dev_null(void) {
        struct stat dst, ost, est;

        if (cached_on_dev_null >= 0)
                return cached_on_dev_null;

        if (stat("/dev/null", &dst) < 0 || fstat(STDOUT_FILENO, &ost) < 0 || fstat(STDERR_FILENO, &est) < 0)
                cached_on_dev_null = false;
        else
                cached_on_dev_null = stat_inode_same(&dst, &ost) && stat_inode_same(&dst, &est);

        return cached_on_dev_null;
}

bool getenv_terminal_is_dumb(void) {
        const char *e;

        e = getenv("TERM");
        if (!e)
                return true;

        return streq(e, "dumb");
}

bool terminal_is_dumb(void) {
        if (!on_tty() && !on_dev_null())
                return true;

        return getenv_terminal_is_dumb();
}

static ColorMode parse_systemd_colors(void) {
        const char *e;
        int r;

        e = getenv("SYSTEMD_COLORS");
        if (!e)
                return _COLOR_INVALID;
        if (streq(e, "16"))
                return COLOR_16;
        if (streq(e, "256"))
                return COLOR_256;
        r = parse_boolean(e);
        if (r >= 0)
                return r > 0 ? COLOR_ON : COLOR_OFF;
        return _COLOR_INVALID;
}

ColorMode get_color_mode(void) {

        /* Returns the mode used to choose output colors. The possible modes are COLOR_OFF for no colors,
         * COLOR_16 for only the base 16 ANSI colors, COLOR_256 for more colors and COLOR_ON for unrestricted
         * color output. For that we check $SYSTEMD_COLORS first (which is the explicit way to
         * change the mode). If that didn't work we turn colors off unless we are on a TTY. And if we are on a TTY
         * we turn it off if $TERM is set to "dumb". There's one special tweak though: if we are PID 1 then we do not
         * check whether we are connected to a TTY, because we don't keep /dev/console open continuously due to fear
         * of SAK, and hence things are a bit weird. */
        ColorMode m;

        if (cached_color_mode < 0) {
                m = parse_systemd_colors();
                if (m >= 0)
                        cached_color_mode = m;
                else if (getenv("NO_COLOR"))
                        /* We only check for the presence of the variable; value is ignored. */
                        cached_color_mode = COLOR_OFF;

                else if (getpid_cached() == 1) {
                        /* PID1 outputs to the console without holding it open all the time.
                         *
                         * Note that the Linux console can only display 16 colors. We still enable 256 color
                         * mode even for PID1 output though (which typically goes to the Linux console),
                         * since the Linux console is able to parse the 256 color sequences and automatically
                         * map them to the closest color in the 16 color palette (since kernel 3.16). Doing
                         * 256 colors is nice for people who invoke systemd in a container or via a serial
                         * link or such, and use a true 256 color terminal to do so. */
                        if (getenv_terminal_is_dumb())
                                cached_color_mode = COLOR_OFF;
                } else {
                        if (terminal_is_dumb())
                                cached_color_mode = COLOR_OFF;
                }

                if (cached_color_mode < 0) {
                        /* We failed to figure out any reason to *disable* colors.
                         * Let's see how many colors we shall use. */
                        if (STRPTR_IN_SET(getenv("COLORTERM"),
                                          "truecolor",
                                          "24bit"))
                                cached_color_mode = COLOR_24BIT;
                        else
                                cached_color_mode = COLOR_256;
                }
        }

        return cached_color_mode;
}

bool underline_enabled(void) {

        if (cached_underline_enabled < 0) {

                /* The Linux console doesn't support underlining, turn it off, but only there. */

                if (colors_enabled())
                        cached_underline_enabled = !streq_ptr(getenv("TERM"), "linux");
                else
                        cached_underline_enabled = false;
        }

        return cached_underline_enabled;
}
