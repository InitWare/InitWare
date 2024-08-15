#pragma once

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

#include <sys/time.h>

#include <inttypes.h>
#include <stdio.h>

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

#define PRI_NSEC PRIu64
#define PRI_USEC PRIu64
#define NSEC_FMT "%" PRI_NSEC
#define USEC_FMT "%" PRI_USEC

#include "macro.h"

typedef struct dual_timestamp {
	usec_t realtime;
	usec_t monotonic;
} dual_timestamp;

typedef enum TimestampStyle {
        TIMESTAMP_PRETTY,
        TIMESTAMP_US,
        TIMESTAMP_UTC,
        TIMESTAMP_US_UTC,
        TIMESTAMP_UNIX,
        TIMESTAMP_DATE,
        _TIMESTAMP_STYLE_MAX,
        _TIMESTAMP_STYLE_INVALID = -EINVAL,
} TimestampStyle;

#define USEC_INFINITY ((usec_t)-1)
#define NSEC_INFINITY ((nsec_t)-1)

#define MSEC_PER_SEC 1000ULL
#define USEC_PER_SEC ((usec_t)1000000ULL)
#define USEC_PER_MSEC ((usec_t)1000ULL)
#define NSEC_PER_SEC ((nsec_t)1000000000ULL)
#define NSEC_PER_MSEC ((nsec_t)1000000ULL)
#define NSEC_PER_USEC ((nsec_t)1000ULL)

#define USEC_PER_MINUTE ((usec_t)(60ULL * USEC_PER_SEC))
#define NSEC_PER_MINUTE ((nsec_t)(60ULL * NSEC_PER_SEC))
#define USEC_PER_HOUR ((usec_t)(60ULL * USEC_PER_MINUTE))
#define NSEC_PER_HOUR ((nsec_t)(60ULL * NSEC_PER_MINUTE))
#define USEC_PER_DAY ((usec_t)(24ULL * USEC_PER_HOUR))
#define NSEC_PER_DAY ((nsec_t)(24ULL * NSEC_PER_HOUR))
#define USEC_PER_WEEK ((usec_t)(7ULL * USEC_PER_DAY))
#define NSEC_PER_WEEK ((nsec_t)(7ULL * NSEC_PER_DAY))
#define USEC_PER_MONTH ((usec_t)(2629800ULL * USEC_PER_SEC))
#define NSEC_PER_MONTH ((nsec_t)(2629800ULL * NSEC_PER_SEC))
#define USEC_PER_YEAR ((usec_t)(31557600ULL * USEC_PER_SEC))
#define NSEC_PER_YEAR ((nsec_t)(31557600ULL * NSEC_PER_SEC))

#define FORMAT_TIMESTAMP_MAX                                                   \
	((4 * 4 + 1) + 11 + 9 + 4 + 1) /* weekdays can be unicode */
#define FORMAT_TIMESTAMP_WIDTH 28 /* when outputting, assume this width */
#define FORMAT_TIMESTAMP_RELATIVE_MAX 256
#define FORMAT_TIMESPAN_MAX 64

char* format_timestamp_style(char *buf, size_t l, usec_t t, TimestampStyle style) _warn_unused_result_;
_warn_unused_result_
static inline char* format_timestamp(char *buf, size_t l, usec_t t) {
        return format_timestamp_style(buf, l, t, TIMESTAMP_PRETTY);
}
#define FORMAT_TIMESTAMP(t) format_timestamp((char[FORMAT_TIMESTAMP_MAX]){}, FORMAT_TIMESTAMP_MAX, t)

char* format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy) _warn_unused_result_;
#define FORMAT_TIMESPAN(t, accuracy) format_timespan((char[FORMAT_TIMESPAN_MAX]){}, FORMAT_TIMESPAN_MAX, t, accuracy)

#define TIME_T_MAX (time_t)((1UL << ((sizeof(time_t) << 3) - 1)) - 1)

#define DUAL_TIMESTAMP_NULL ((struct dual_timestamp){ 0ULL, 0ULL })

usec_t now(clockid_t clock);

dual_timestamp* dual_timestamp_now(dual_timestamp *ts);
dual_timestamp *dual_timestamp_get(dual_timestamp *ts);
dual_timestamp *dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u);
dual_timestamp *dual_timestamp_from_monotonic(dual_timestamp *ts, usec_t u);

static inline bool timestamp_is_set(usec_t timestamp) {
        return timestamp > 0 && timestamp != USEC_INFINITY;
}

static inline bool
dual_timestamp_is_set(dual_timestamp *ts)
{
	return ((ts->realtime > 0 && ts->realtime != USEC_INFINITY) ||
		(ts->monotonic > 0 && ts->monotonic != USEC_INFINITY));
}

usec_t timespec_load(const struct timespec *ts) _pure_;
struct timespec *timespec_store(struct timespec *ts, usec_t u);

usec_t timeval_load(const struct timeval *tv) _pure_;
struct timeval *timeval_store(struct timeval *tv, usec_t u);

char *format_timestamp_utc(char *buf, size_t l, usec_t t);
char *format_timestamp_us(char *buf, size_t l, usec_t t);
char *format_timestamp_us_utc(char *buf, size_t l, usec_t t);
char *format_timestamp_relative(char *buf, size_t l, usec_t t);
char *format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy);

void dual_timestamp_serialize(FILE *f, const char *name, dual_timestamp *t);
void dual_timestamp_deserialize(const char *value, dual_timestamp *t);

int parse_timestamp(const char *t, usec_t *usec);

int parse_sec(const char *t, usec_t *usec);
int parse_time(const char *t, usec_t *usec, usec_t default_unit);
int parse_nsec(const char *t, nsec_t *nsec);

bool ntp_synced(void);

int get_timezones(char ***l);
bool timezone_is_valid(const char *name);

struct tm *localtime_or_gmtime_r(const time_t *t, struct tm *tm, bool utc);

clockid_t clock_boottime_or_monotonic(void);

/* The last second we can format is 31. Dec 9999, 1s before midnight, because otherwise we'd enter 5 digit
 * year territory. However, since we want to stay away from this in all timezones we take one day off. */
#define USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT ((usec_t) 253402214399000000) /* Thu 9999-12-30 23:59:59 UTC */
/* With a 32-bit time_t we can't go beyond 2038...
 * We parse timestamp with RFC-822/ISO 8601 (e.g. +06, or -03:00) as UTC, hence the upper bound must be off
 * by USEC_PER_DAY. See parse_timestamp() for more details. */
#define USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT (((usec_t) INT32_MAX) * USEC_PER_SEC - USEC_PER_DAY)
#if SVC_SIZEOF_TIME_T == 8
#  define USEC_TIMESTAMP_FORMATTABLE_MAX USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT
#elif SVC_SIZEOF_TIME_T == 4
#  define USEC_TIMESTAMP_FORMATTABLE_MAX USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT
#else
#  error "Yuck, time_t is neither 4 nor 8 bytes wide?"
#endif
