/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#pragma once

#include "journal-remote-write.h"
#include "sd-event.h"

typedef enum {
	STATE_LINE = 0, /* waiting to read, or reading line */
	STATE_DATA_START, /* reading binary data header */
	STATE_DATA, /* reading binary data */
	STATE_DATA_FINISH, /* expecting newline */
	STATE_EOF, /* done */
} source_state;

typedef struct RemoteSource {
	char *name;
	int fd;
	bool passive_fd;

	char *buf;
	size_t size; /* total size of the buffer */
	size_t offset; /* offset to the beginning of live data in the buffer */
	size_t scanned; /* number of bytes since the beginning of data without a newline */
	size_t filled; /* total number of bytes in the buffer */

	size_t field_len; /* used for binary fields: the field name length */
	size_t data_size; /* and the size of the binary data chunk being processed */

	struct iovec_wrapper iovw;

	source_state state;
	dual_timestamp ts;

	Writer *writer;

	sd_event_source *event;
	sd_event_source *buffer_event;
} RemoteSource;

RemoteSource *source_new(int fd, bool passive_fd, char *name, Writer *writer);

static inline size_t
source_non_empty(RemoteSource *source)
{
	assert(source);

	return source->filled;
}

void source_free(RemoteSource *source);
int process_data(RemoteSource *source);
int push_data(RemoteSource *source, const char *data, size_t size);
int process_source(RemoteSource *source, bool compress, bool seal);
