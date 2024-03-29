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

int detect_vm(const char **id);
int detect_container(const char **id);

enum {
	VIRTUALIZATION_NONE = 0,
	VIRTUALIZATION_VM,
	VIRTUALIZATION_CONTAINER,
	_VIRTUALIZATION_MAX,
	_VIRTUALIZATION_INVALID = -1
};

int detect_virtualization(const char **id);
