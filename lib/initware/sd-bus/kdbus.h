/*
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef _KDBUS_UAPI_H_
#define _KDBUS_UAPI_H_

/**
 * enum kdbus_attach_flags - flags for metadata attachments
 * @KDBUS_ATTACH_TIMESTAMP:		Timestamp
 * @KDBUS_ATTACH_CREDS:			Credentials
 * @KDBUS_ATTACH_PIDS:			PIDs
 * @KDBUS_ATTACH_AUXGROUPS:		Auxiliary groups
 * @KDBUS_ATTACH_NAMES:			Well-known names
 * @KDBUS_ATTACH_TID_COMM:		The "comm" process identifier of the TID
 * @KDBUS_ATTACH_PID_COMM:		The "comm" process identifier of the PID
 * @KDBUS_ATTACH_EXE:			The path of the executable
 * @KDBUS_ATTACH_CMDLINE:		The process command line
 * @KDBUS_ATTACH_CGROUP:		The croup membership
 * @KDBUS_ATTACH_CAPS:			The process capabilities
 * @KDBUS_ATTACH_SECLABEL:		The security label
 * @KDBUS_ATTACH_AUDIT:			The audit IDs
 * @KDBUS_ATTACH_CONN_DESCRIPTION:	The human-readable connection name
 * @_KDBUS_ATTACH_ALL:			All of the above
 * @_KDBUS_ATTACH_ANY:			Wildcard match to enable any kind of
 *					metatdata.
 */
enum kdbus_attach_flags {
	KDBUS_ATTACH_TIMESTAMP = 1ULL << 0,
	KDBUS_ATTACH_CREDS = 1ULL << 1,
	KDBUS_ATTACH_PIDS = 1ULL << 2,
	KDBUS_ATTACH_AUXGROUPS = 1ULL << 3,
	KDBUS_ATTACH_NAMES = 1ULL << 4,
	KDBUS_ATTACH_TID_COMM = 1ULL << 5,
	KDBUS_ATTACH_PID_COMM = 1ULL << 6,
	KDBUS_ATTACH_EXE = 1ULL << 7,
	KDBUS_ATTACH_CMDLINE = 1ULL << 8,
	KDBUS_ATTACH_CGROUP = 1ULL << 9,
	KDBUS_ATTACH_CAPS = 1ULL << 10,
	KDBUS_ATTACH_SECLABEL = 1ULL << 11,
	KDBUS_ATTACH_AUDIT = 1ULL << 12,
	KDBUS_ATTACH_CONN_DESCRIPTION = 1ULL << 13,
	_KDBUS_ATTACH_ALL = (1ULL << 14) - 1,
	_KDBUS_ATTACH_ANY = ~0ULL
};

/**
 * enum kdbus_hello_flags - flags for struct kdbus_cmd_hello
 * @KDBUS_HELLO_ACCEPT_FD:	The connection allows the reception of
 *				any passed file descriptors
 * @KDBUS_HELLO_ACTIVATOR:	Special-purpose connection which registers
 *				a well-know name for a process to be started
 *				when traffic arrives
 * @KDBUS_HELLO_POLICY_HOLDER:	Special-purpose connection which registers
 *				policy entries for a name. The provided name
 *				is not activated and not registered with the
 *				name database, it only allows unprivileged
 *				connections to acquire a name, talk or discover
 *				a service
 * @KDBUS_HELLO_MONITOR:	Special-purpose connection to monitor
 *				bus traffic
 */
enum kdbus_hello_flags {
	KDBUS_HELLO_ACCEPT_FD = 1ULL << 0,
	KDBUS_HELLO_ACTIVATOR = 1ULL << 1,
	KDBUS_HELLO_POLICY_HOLDER = 1ULL << 2,
	KDBUS_HELLO_MONITOR = 1ULL << 3,
};

#endif /* _KDBUS_UAPI_H_ */
