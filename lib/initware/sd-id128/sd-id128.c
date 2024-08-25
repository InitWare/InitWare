/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "chase.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "io-util.h"
#include "macro.h"
#include "path-util.h"
#include "random-util.h"
#include "sd-id128.h"
#include "util.h"

_public_ char *
sd_id128_to_string(sd_id128_t id, char s[33])
{
	unsigned n;

	assert_return(s, NULL);

	for (n = 0; n < 16; n++) {
		s[n * 2] = hexchar(id.bytes[n] >> 4);
		s[n * 2 + 1] = hexchar(id.bytes[n] & 0xF);
	}

	s[32] = 0;

	return s;
}

_public_ char *sd_id128_to_uuid_string(sd_id128_t id, char s[SD_ID128_UUID_STRING_MAX]) {
        size_t k = 0;

        assert_return(s, NULL);

        /* Similar to sd_id128_to_string() but formats the result as UUID instead of plain hex chars */

        for (size_t n = 0; n < sizeof(sd_id128_t); n++) {

                if (IN_SET(n, 4, 6, 8, 10))
                        s[k++] = '-';

                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == SD_ID128_UUID_STRING_MAX - 1);
        s[k] = 0;

        return s;
}

_public_ int
sd_id128_from_string(const char s[], sd_id128_t *ret)
{
	unsigned n, i;
	sd_id128_t t;
	bool is_guid = false;

	assert_return(s, -EINVAL);
	assert_return(ret, -EINVAL);

	for (n = 0, i = 0; n < 16;) {
		int a, b;

		if (s[i] == '-') {
			/* Is this a GUID? Then be nice, and skip over
                         * the dashes */

			if (i == 8)
				is_guid = true;
			else if (i == 13 || i == 18 || i == 23) {
				if (!is_guid)
					return -EINVAL;
			} else
				return -EINVAL;

			i++;
			continue;
		}

		a = unhexchar(s[i++]);
		if (a < 0)
			return -EINVAL;

		b = unhexchar(s[i++]);
		if (b < 0)
			return -EINVAL;

		t.bytes[n++] = (a << 4) | b;
	}

	if (i != (is_guid ? 36 : 32))
		return -EINVAL;

	if (s[i] != 0)
		return -EINVAL;

	*ret = t;
	return 0;
}

_public_ int sd_id128_get_machine(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_machine_id = {};
        int r;

        if (sd_id128_is_null(saved_machine_id)) {
                r = id128_read("/etc/machine-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, &saved_machine_id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = saved_machine_id;
        return 0;
}

int id128_get_machine(const char *root, sd_id128_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        if (empty_or_root(root))
                return sd_id128_get_machine(ret);

        fd = chase_and_open("/etc/machine-id", root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
        if (fd < 0)
                return fd;

        return id128_read_fd(fd, ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, ret);
}

_public_ int
sd_id128_get_boot(sd_id128_t *ret)
{
	static thread_local sd_id128_t saved_boot_id;
	static thread_local bool saved_boot_id_valid = false;
	_cleanup_close_ int fd = -1;
	char buf[36];
	ssize_t k;
	unsigned j;
	sd_id128_t t;
	char *p;

	assert_return(ret, -EINVAL);

	if (saved_boot_id_valid) {
		*ret = saved_boot_id;
		return 0;
	}

	fd = open("/proc/sys/kernel/random/boot_id",
		O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0)
	{
		// TODO: unique boot ID portability
		// return -errno;
		return sd_id128_get_machine(ret);
	}

	k = loop_read(fd, buf, 36, false);
	if (k < 0)
		return (int)k;

	if (k != 36)
		return -EIO;

	for (j = 0, p = buf; j < 16; j++) {
		int a, b;

		if (p >= buf + k - 1)
			return -EIO;

		if (*p == '-') {
			p++;
			if (p >= buf + k - 1)
				return -EIO;
		}

		a = unhexchar(p[0]);
		b = unhexchar(p[1]);

		if (a < 0 || b < 0)
			return -EIO;

		t.bytes[j] = a << 4 | b;

		p += 2;
	}

	saved_boot_id = t;
	saved_boot_id_valid = true;

	*ret = t;
	return 0;
}

_public_ int sd_id128_randomize(sd_id128_t *ret) {
        sd_id128_t t;

        assert_return(ret, -EINVAL);

        random_bytes(&t, sizeof(t));

        /* Turn this into a valid v4 UUID, to be nice. Note that we
         * only guarantee this for newly generated UUIDs, not for
         * pre-existing ones. */

        *ret = id128_make_v4_uuid(t);
        return 0;
}
