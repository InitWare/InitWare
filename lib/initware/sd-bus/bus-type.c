/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "bus-internal.h"
#include "bus-type.h"
#include "util.h"

bool
bus_type_is_valid(char c)
{
	static const char valid[] = { SD_BUS_TYPE_BYTE, SD_BUS_TYPE_BOOLEAN,
		SD_BUS_TYPE_INT16, SD_BUS_TYPE_UINT16, SD_BUS_TYPE_INT32,
		SD_BUS_TYPE_UINT32, SD_BUS_TYPE_INT64, SD_BUS_TYPE_UINT64,
		SD_BUS_TYPE_DOUBLE, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH,
		SD_BUS_TYPE_SIGNATURE, SD_BUS_TYPE_ARRAY, SD_BUS_TYPE_VARIANT,
		SD_BUS_TYPE_STRUCT, SD_BUS_TYPE_DICT_ENTRY,
		SD_BUS_TYPE_UNIX_FD };

	return !!memchr(valid, c, sizeof(valid));
}

bool
bus_type_is_valid_in_signature(char c)
{
	static const char valid[] = { SD_BUS_TYPE_BYTE, SD_BUS_TYPE_BOOLEAN,
		SD_BUS_TYPE_INT16, SD_BUS_TYPE_UINT16, SD_BUS_TYPE_INT32,
		SD_BUS_TYPE_UINT32, SD_BUS_TYPE_INT64, SD_BUS_TYPE_UINT64,
		SD_BUS_TYPE_DOUBLE, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH,
		SD_BUS_TYPE_SIGNATURE, SD_BUS_TYPE_ARRAY, SD_BUS_TYPE_VARIANT,
		SD_BUS_TYPE_STRUCT_BEGIN, SD_BUS_TYPE_STRUCT_END,
		SD_BUS_TYPE_DICT_ENTRY_BEGIN, SD_BUS_TYPE_DICT_ENTRY_END,
		SD_BUS_TYPE_UNIX_FD };

	return !!memchr(valid, c, sizeof(valid));
}

bool
bus_type_is_basic(char c)
{
	static const char valid[] = { SD_BUS_TYPE_BYTE, SD_BUS_TYPE_BOOLEAN,
		SD_BUS_TYPE_INT16, SD_BUS_TYPE_UINT16, SD_BUS_TYPE_INT32,
		SD_BUS_TYPE_UINT32, SD_BUS_TYPE_INT64, SD_BUS_TYPE_UINT64,
		SD_BUS_TYPE_DOUBLE, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH,
		SD_BUS_TYPE_SIGNATURE, SD_BUS_TYPE_UNIX_FD };

	return !!memchr(valid, c, sizeof(valid));
}

bool
bus_type_is_trivial(char c)
{
	static const char valid[] = { SD_BUS_TYPE_BYTE, SD_BUS_TYPE_BOOLEAN,
		SD_BUS_TYPE_INT16, SD_BUS_TYPE_UINT16, SD_BUS_TYPE_INT32,
		SD_BUS_TYPE_UINT32, SD_BUS_TYPE_INT64, SD_BUS_TYPE_UINT64,
		SD_BUS_TYPE_DOUBLE };

	return !!memchr(valid, c, sizeof(valid));
}

bool
bus_type_is_container(char c)
{
	static const char valid[] = { SD_BUS_TYPE_ARRAY, SD_BUS_TYPE_VARIANT,
		SD_BUS_TYPE_STRUCT, SD_BUS_TYPE_DICT_ENTRY };

	return !!memchr(valid, c, sizeof(valid));
}

int
bus_type_get_alignment(char c)
{
	switch (c) {
	case SD_BUS_TYPE_BYTE:
	case SD_BUS_TYPE_SIGNATURE:
	case SD_BUS_TYPE_VARIANT:
		return 1;

	case SD_BUS_TYPE_INT16:
	case SD_BUS_TYPE_UINT16:
		return 2;

	case SD_BUS_TYPE_BOOLEAN:
	case SD_BUS_TYPE_INT32:
	case SD_BUS_TYPE_UINT32:
	case SD_BUS_TYPE_STRING:
	case SD_BUS_TYPE_OBJECT_PATH:
	case SD_BUS_TYPE_ARRAY:
	case SD_BUS_TYPE_UNIX_FD:
		return 4;

	case SD_BUS_TYPE_INT64:
	case SD_BUS_TYPE_UINT64:
	case SD_BUS_TYPE_DOUBLE:
	case SD_BUS_TYPE_STRUCT:
	case SD_BUS_TYPE_STRUCT_BEGIN:
	case SD_BUS_TYPE_DICT_ENTRY:
	case SD_BUS_TYPE_DICT_ENTRY_BEGIN:
		return 8;
	}

	return -EINVAL;
}

int
bus_type_get_size(char c)
{
	switch (c) {
	case SD_BUS_TYPE_BYTE:
		return 1;

	case SD_BUS_TYPE_INT16:
	case SD_BUS_TYPE_UINT16:
		return 2;

	case SD_BUS_TYPE_BOOLEAN:
	case SD_BUS_TYPE_INT32:
	case SD_BUS_TYPE_UINT32:
	case SD_BUS_TYPE_UNIX_FD:
		return 4;

	case SD_BUS_TYPE_INT64:
	case SD_BUS_TYPE_UINT64:
	case SD_BUS_TYPE_DOUBLE:
		return 8;
	}

	return -EINVAL;
}

_public_ int sd_bus_service_name_is_valid(const char *p) {
        assert_return(p, -EINVAL);

        return service_name_is_valid(p);
}
