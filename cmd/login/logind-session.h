/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

typedef struct Session Session;
typedef enum KillWho KillWho;

#include "list.h"
#include "util.h"
#include "logind.h"
#include "logind-seat.h"
#include "logind-session-device.h"
#include "logind-user.h"
#include "login-shared.h"

typedef enum SessionState {
        SESSION_OPENING,  /* Session scope is being created */
        SESSION_ONLINE,   /* Logged in */
        SESSION_ACTIVE,   /* Logged in and in the fg */
        SESSION_CLOSING,  /* Logged out, but scope is still there */
        _SESSION_STATE_MAX,
        _SESSION_STATE_INVALID = -1
} SessionState;

typedef enum SessionClass {
        SESSION_USER,
        SESSION_GREETER,
        SESSION_LOCK_SCREEN,
        SESSION_BACKGROUND,
        _SESSION_CLASS_MAX,
        _SESSION_CLASS_INVALID = -1
} SessionClass;

typedef enum SessionType {
        SESSION_UNSPECIFIED,
        SESSION_TTY,
        SESSION_X11,
        _SESSION_TYPE_MAX,
        _SESSION_TYPE_INVALID = -1
} SessionType;

enum KillWho {
        KILL_LEADER,
        KILL_ALL,
        _KILL_WHO_MAX,
        _KILL_WHO_INVALID = -1
};

struct Session {
        Manager *manager;

        char *id;
        SessionType type;
        SessionClass class;

        char *state_file;

        User *user;

        dual_timestamp timestamp;

        char *tty;
        char *display;

        bool remote;
        char *remote_user;
        char *remote_host;
        char *service;

        char *scope;
        char *scope_job;

        int vtnr;
        Seat *seat;

        pid_t leader;
        uint32_t audit_id;

        ev_io fifo_watch;
        char *fifo_path;

        ev_timer release_timer;

        bool idle_hint;
        dual_timestamp idle_hint_timestamp;

        bool in_gc_queue:1;
        bool started:1;
        bool stopping:1;
        bool closing:1;

        DBusMessage *create_message;

        char *controller;
        Hashmap *devices;

        IWLIST_FIELDS(Session, sessions_by_user);
        IWLIST_FIELDS(Session, sessions_by_seat);

        IWLIST_FIELDS(Session, gc_queue);
};

Session *session_new(Manager *m, const char *id);
void session_free(Session *s);
void session_set_user(Session *s, User *u);
int session_check_gc(Session *s, bool drop_not_started);
void session_add_to_gc_queue(Session *s);
int session_activate(Session *s);
bool session_is_active(Session *s);
int session_get_idle_hint(Session *s, dual_timestamp *t);
void session_set_idle_hint(Session *s, bool b);
int session_create_fifo(Session *s);
void session_remove_fifo(Session *s);
int session_start(Session *s);
int session_stop(Session *s);
int session_finalize(Session *s);
void session_release(Session *s);
int session_save(Session *s);
int session_load(Session *s);
int session_kill(Session *s, KillWho who, int signo);

char *session_bus_path(Session *s);

SessionState session_get_state(Session *u);

extern const DBusObjectPathVTable bus_session_vtable;

int session_send_signal(Session *s, bool new_session);
int session_send_changed(Session *s, const char *properties);
int session_send_lock(Session *s, bool lock);
int session_send_lock_all(Manager *m, bool lock);

int session_send_create_reply(Session *s, DBusError *error);

const char* session_state_to_string(SessionState t) _const_;
SessionState session_state_from_string(const char *s) _pure_;

const char* session_type_to_string(SessionType t) _const_;
SessionType session_type_from_string(const char *s) _pure_;

const char* session_class_to_string(SessionClass t) _const_;
SessionClass session_class_from_string(const char *s) _pure_;

const char *kill_who_to_string(KillWho k) _const_;
KillWho kill_who_from_string(const char *s) _pure_;

bool session_is_controller(Session *s, const char *sender);
int session_set_controller(Session *s, const char *sender, bool force);
void session_drop_controller(Session *s);
