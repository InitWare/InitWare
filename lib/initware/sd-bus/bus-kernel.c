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

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine lsb_basename() since libgen.h defines it as a macro to the XDG
 * version which is really broken. */
#include <libgen.h>
#undef basename

#include "capability.h"
#include "cgroup-util.h"
#include "fileio.h"
#include "memfd-util.h"
#include "strv.h"
#include "util.h"

#include "bus-internal.h"
#include "bus-kernel.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-util.h"

uint64_t
attach_flags_to_kdbus(uint64_t mask)
{
	uint64_t m = 0;

	if (mask &
		(SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_SUID |
			SD_BUS_CREDS_FSUID | SD_BUS_CREDS_GID |
			SD_BUS_CREDS_EGID | SD_BUS_CREDS_SGID |
			SD_BUS_CREDS_FSGID))
		m |= KDBUS_ATTACH_CREDS;

	if (mask & (SD_BUS_CREDS_PID | SD_BUS_CREDS_TID))
		m |= KDBUS_ATTACH_PIDS;

	if (mask & SD_BUS_CREDS_COMM)
		m |= KDBUS_ATTACH_PID_COMM;

	if (mask & SD_BUS_CREDS_TID_COMM)
		m |= KDBUS_ATTACH_TID_COMM;

	if (mask & SD_BUS_CREDS_EXE)
		m |= KDBUS_ATTACH_EXE;

	if (mask & SD_BUS_CREDS_CMDLINE)
		m |= KDBUS_ATTACH_CMDLINE;

	if (mask &
		(SD_BUS_CREDS_CGROUP | SD_BUS_CREDS_UNIT |
			SD_BUS_CREDS_USER_UNIT | SD_BUS_CREDS_SLICE |
			SD_BUS_CREDS_SESSION | SD_BUS_CREDS_OWNER_UID))
		m |= KDBUS_ATTACH_CGROUP;

	if (mask &
		(SD_BUS_CREDS_EFFECTIVE_CAPS | SD_BUS_CREDS_PERMITTED_CAPS |
			SD_BUS_CREDS_INHERITABLE_CAPS |
			SD_BUS_CREDS_BOUNDING_CAPS))
		m |= KDBUS_ATTACH_CAPS;

	if (mask & SD_BUS_CREDS_SELINUX_CONTEXT)
		m |= KDBUS_ATTACH_SECLABEL;

	if (mask &
		(SD_BUS_CREDS_AUDIT_SESSION_ID | SD_BUS_CREDS_AUDIT_LOGIN_UID))
		m |= KDBUS_ATTACH_AUDIT;

	if (mask & SD_BUS_CREDS_WELL_KNOWN_NAMES)
		m |= KDBUS_ATTACH_NAMES;

	if (mask & SD_BUS_CREDS_DESCRIPTION)
		m |= KDBUS_ATTACH_CONN_DESCRIPTION;

	if (mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS)
		m |= KDBUS_ATTACH_AUXGROUPS;

	return m;
}