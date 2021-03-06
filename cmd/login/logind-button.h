/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologindbuttonhfoo
#define foologindbuttonhfoo

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

typedef struct Button Button;

#include "list.h"
#include "util.h"
#include "logind.h"

struct Button {
        Manager *manager;

        char *name;
        char *seat;
        int fd;
        ev_io watch;

        bool lid_close_queued;
};

Button* button_new(Manager *m, const char *name);
void button_free(Button*b);
int button_open(Button *b);
int button_process(Button *b);
int button_recheck(Button *b);
int button_set_seat(Button *b, const char *sn);

#endif
