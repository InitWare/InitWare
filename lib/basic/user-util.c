/* SPDX-License-Identifier: LGPL-2.1-or-later */

// #include <errno.h>
// #include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/file.h>
// #include <sys/stat.h>
// #include <unistd.h>
// #include <utmp.h>

// #include "sd-messages.h"

// #include "alloc-util.h"
// #include "chase.h"
// #include "errno-util.h"
// #include "fd-util.h"
// #include "fileio.h"
// #include "format-util.h"
// #include "lock-util.h"
// #include "macro.h"
// #include "mkdir.h"
// #include "parse-util.h"
// #include "path-util.h"
// #include "random-util.h"
// #include "string-util.h"
// #include "strv.h"
#include "user-util.h"
// #include "utf8.h"

bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16 bit, hence explicitly avoid the 16-bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}
