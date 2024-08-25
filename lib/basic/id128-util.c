/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "fs-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "string-util.h"

int id128_read_fd(int fd, Id128Flag f, sd_id128_t *ret) {
        char buffer[SD_ID128_UUID_STRING_MAX + 1]; /* +1 is for trailing newline */
        sd_id128_t id;
        ssize_t l;
        int r;

        assert(fd >= 0);

        /* Reads an 128-bit ID from a file, which may either be in plain format (32 hex digits), or in UUID format, both
         * optionally followed by a newline and nothing else. ID files should really be newline terminated, but if they
         * aren't that's OK too, following the rule of "Be conservative in what you send, be liberal in what you
         * accept".
         *
         * This returns the following:
         *     -ENOMEDIUM: an empty string,
         *     -ENOPKG:    "uninitialized" or "uninitialized\n",
         *     -EUCLEAN:   other invalid strings. */

        l = loop_read(fd, buffer, sizeof(buffer), false); /* we expect a short read of either 32/33 or 36/37 chars */
        if (l < 0)
                return (int) l;
        if (l == 0) /* empty? */
                return -ENOMEDIUM;

        switch (l) {

        case STRLEN("uninitialized"):
        case STRLEN("uninitialized\n"):
                return strneq(buffer, "uninitialized\n", l) ? -ENOPKG : -EINVAL;

        case SD_ID128_STRING_MAX: /* plain UUID with trailing newline */
                if (buffer[SD_ID128_STRING_MAX-1] != '\n')
                        return -EUCLEAN;

                _fallthrough_;
        case SD_ID128_STRING_MAX-1: /* plain UUID without trailing newline */
                if (!FLAGS_SET(f, ID128_FORMAT_PLAIN))
                        return -EUCLEAN;

                buffer[SD_ID128_STRING_MAX-1] = 0;
                break;

        case SD_ID128_UUID_STRING_MAX: /* RFC UUID with trailing newline */
                if (buffer[SD_ID128_UUID_STRING_MAX-1] != '\n')
                        return -EUCLEAN;

                _fallthrough_;
        case SD_ID128_UUID_STRING_MAX-1: /* RFC UUID without trailing newline */
                if (!FLAGS_SET(f, ID128_FORMAT_UUID))
                        return -EUCLEAN;

                buffer[SD_ID128_UUID_STRING_MAX-1] = 0;
                break;

        default:
                return -EUCLEAN;
        }

        r = sd_id128_from_string(buffer, &id);
        if (r == -EINVAL)
                return -EUCLEAN;
        if (r < 0)
                return r;

        if (FLAGS_SET(f, ID128_REFUSE_NULL) && sd_id128_is_null(id))
                return -ENOMEDIUM;

        if (ret)
                *ret = id;
        return 0;
}

int id128_read_at(int dir_fd, const char *path, Id128Flag f, sd_id128_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        fd = xopenat(dir_fd, path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return fd;

        return id128_read_fd(fd, f, ret);
}

sd_id128_t id128_make_v4_uuid(sd_id128_t id) {
        /* Stolen from generate_random_uuid() of drivers/char/random.c
         * in the kernel sources */

        /* Set UUID version to 4 --- truly random generation */
        id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

        /* Set the UUID variant to DCE */
        id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;

        return id;
}
