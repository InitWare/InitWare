/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Lennart Poettering
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * "Everything should be made as simple as possible, but not simpler."
 *   -- Albert Einstein
 */

#ifndef _KDBUS_H_
#define _KDBUS_H_

#include <sys/types.h>
#include <sys/ioctl.h>

#define KDBUS_IOC_MAGIC 0x95
#define KDBUS_SRC_ID_KERNEL (0)
#define KDBUS_DST_ID_NAME (0)
#define KDBUS_MATCH_ID_ANY (~0ULL)
#define KDBUS_DST_ID_BROADCAST (~0ULL)


/**
 * enum kdbus_hello_flags - flags for struct kdbus_cmd_hello
 * @KDBUS_HELLO_ACCEPT_FD:	The connection allows the receiving of
 *				any passed file descriptors
 * @KDBUS_HELLO_ACTIVATOR:	Special-purpose connection which registers
 *				a well-know name for a process to be started
 *				when traffic arrives
 * @KDBUS_HELLO_MONITOR:	Special-purpose connection to monitor
 *				bus traffic
 */
enum kdbus_hello_flags {
	KDBUS_HELLO_ACCEPT_FD = 1 << 0,
	KDBUS_HELLO_ACTIVATOR = 1 << 1,
	KDBUS_HELLO_MONITOR = 1 << 2,
};

/**
 * enum kdbus_attach_flags - flags for metadata attachments
 * @KDBUS_ATTACH_TIMESTAMP:	Timestamp
 * @KDBUS_ATTACH_CREDS:		Credentials
 * @KDBUS_ATTACH_NAMES:		Well-known names
 * @KDBUS_ATTACH_COMM:		The "comm" process identifier
 * @KDBUS_ATTACH_EXE:		The path of the executable
 * @KDBUS_ATTACH_CMDLINE:	The process command line
 * @KDBUS_ATTACH_CGROUP:	The croup membership
 * @KDBUS_ATTACH_CAPS:		The process capabilities
 * @KDBUS_ATTACH_SECLABEL:	The security label
 * @KDBUS_ATTACH_AUDIT:		The audit IDs
 * @KDBUS_ATTACH_CONN_NAME:	The human-readable connection name
 */
enum kdbus_attach_flags {
	KDBUS_ATTACH_TIMESTAMP = 1 << 0,
	KDBUS_ATTACH_CREDS = 1 << 1,
	KDBUS_ATTACH_NAMES = 1 << 2,
	KDBUS_ATTACH_COMM = 1 << 3,
	KDBUS_ATTACH_EXE = 1 << 4,
	KDBUS_ATTACH_CMDLINE = 1 << 5,
	KDBUS_ATTACH_CGROUP = 1 << 6,
	KDBUS_ATTACH_CAPS = 1 << 7,
	KDBUS_ATTACH_SECLABEL = 1 << 8,
	KDBUS_ATTACH_AUDIT = 1 << 9,
	KDBUS_ATTACH_CONN_NAME = 1 << 10,
};

#endif
