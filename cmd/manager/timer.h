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

#ifndef TIMER_H_
#define TIMER_H_

typedef struct Timer Timer;

#include "ev.h"

#include "unit.h"
#include "calendarspec.h"

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_WAITING,
        TIMER_RUNNING,
        TIMER_ELAPSED,
        TIMER_FAILED,
        _TIMER_STATE_MAX,
        _TIMER_STATE_INVALID = -1
} TimerState;

typedef enum TimerBase {
        TIMER_ACTIVE,
        TIMER_BOOT,
        TIMER_STARTUP,
        TIMER_UNIT_ACTIVE,
        TIMER_UNIT_INACTIVE,
        TIMER_CALENDAR,
        _TIMER_BASE_MAX,
        _TIMER_BASE_INVALID = -1
} TimerBase;

typedef struct TimerValue {
        TimerBase base;
        bool disabled;
        clockid_t clock_id;

        usec_t value; /* only for monotonic events */
        CalendarSpec *calendar_spec; /* only for calendar events */
        usec_t next_elapse;

        IWLIST_FIELDS(struct TimerValue, value);
} TimerValue;

typedef enum TimerResult {
        TIMER_SUCCESS,
        TIMER_FAILURE_RESOURCES,
        _TIMER_RESULT_MAX,
        _TIMER_RESULT_INVALID = -1
} TimerResult;

struct Timer {
        Unit meta;

        IWLIST_HEAD(TimerValue, values);
        usec_t next_elapse_monotonic;
        usec_t next_elapse_realtime;

        TimerState state, deserialized_state;

        ev_timer monotonic_watch;
        ev_periodic realtime_watch;

        TimerResult result;

        usec_t last_trigger_monotonic;
};

void timer_free_values(Timer *t);

extern const UnitVTable timer_vtable;

const char *timer_state_to_string(TimerState i) _const_;
TimerState timer_state_from_string(const char *s) _pure_;

const char *timer_base_to_string(TimerBase i) _const_;
TimerBase timer_base_from_string(const char *s) _pure_;

const char* timer_result_to_string(TimerResult i) _const_;
TimerResult timer_result_from_string(const char *s) _pure_;

void timer_periodic_event(Timer *t, ev_periodic *watch);

#endif