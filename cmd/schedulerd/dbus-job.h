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

#include "job.h"
#include "sd-bus.h"

extern const sd_bus_vtable bus_job_vtable[];

int bus_job_method_cancel(sd_bus_message *message, void *job, sd_bus_error *error);

void bus_job_send_change_signal(Job *j);
void bus_job_send_pending_change_signal(Job *j, bool including_new);
void bus_job_send_removed_signal(Job *j);

int bus_job_track_sender(Job *j, sd_bus_message *m);
