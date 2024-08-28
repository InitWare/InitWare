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

#include <assert.h>

#include "log.h"
#include "ratelimit.h"

/* Modelled after Linux' lib/ratelimit.c by Dave Young
 * <hidave.darkstar@gmail.com>, which is licensed GPLv2. */

bool
ratelimit_test(RateLimit *r)
{
	usec_t ts;

	assert(r);

	if (r->interval <= 0 || r->burst <= 0)
		return true;

	ts = now(CLOCK_MONOTONIC);

	if (r->begin <= 0 || r->begin + r->interval < ts) {
		r->begin = ts;

		/* Reset counter */
		r->num = 0;
		goto good;
	}

	if (r->num < r->burst)
		goto good;

	return false;

good:
	r->num++;
	return true;
}

bool ratelimit_below(RateLimit *r) {
        usec_t ts;

        assert(r);

        if (!ratelimit_configured(r))
                return true;

        ts = now(CLOCK_MONOTONIC);

        if (r->begin <= 0 ||
            usec_sub_unsigned(ts, r->begin) > r->interval) {
                r->begin = ts;  /* Start a new time window */
                r->num = 1;     /* Reset counter */
                return true;
        }

        if (_unlikely_(r->num == UINT_MAX))
                return false;

        r->num++;
        return r->num <= r->burst;
}
