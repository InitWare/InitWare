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
 * enum kdbus_item_type - item types to chain data in a list
 * @_KDBUS_ITEM_NULL:			Uninitialized/invalid
 * @_KDBUS_ITEM_USER_BASE:		Start of user items
 * @KDBUS_ITEM_NEGOTIATE:		Negotiate supported items
 * @KDBUS_ITEM_PAYLOAD_VEC:		Vector to data
 * @KDBUS_ITEM_PAYLOAD_OFF:		Data at returned offset to message head
 * @KDBUS_ITEM_PAYLOAD_MEMFD:		Data as sealed memfd
 * @KDBUS_ITEM_FDS:			Attached file descriptors
 * @KDBUS_ITEM_CANCEL_FD:		FD used to cancel a synchronous
 *					operation by writing to it from
 *					userspace
 * @KDBUS_ITEM_BLOOM_PARAMETER:		Bus-wide bloom parameters, used with
 *					KDBUS_CMD_BUS_MAKE, carries a
 *					struct kdbus_bloom_parameter
 * @KDBUS_ITEM_BLOOM_FILTER:		Bloom filter carried with a message,
 *					used to match against a bloom mask of a
 *					connection, carries a struct
 *					kdbus_bloom_filter
 * @KDBUS_ITEM_BLOOM_MASK:		Bloom mask used to match against a
 *					message'sbloom filter
 * @KDBUS_ITEM_DST_NAME:		Destination's well-known name
 * @KDBUS_ITEM_MAKE_NAME:		Name of domain, bus, endpoint
 * @KDBUS_ITEM_ATTACH_FLAGS_SEND:	Attach-flags, used for updating which
 *					metadata a connection opts in to send
 * @KDBUS_ITEM_ATTACH_FLAGS_RECV:	Attach-flags, used for updating which
 *					metadata a connection requests to
 *					receive for each reeceived message
 * @KDBUS_ITEM_ID:			Connection ID
 * @KDBUS_ITEM_NAME:			Well-know name with flags
 * @_KDBUS_ITEM_ATTACH_BASE:		Start of metadata attach items
 * @KDBUS_ITEM_TIMESTAMP:		Timestamp
 * @KDBUS_ITEM_CREDS:			Process credentials
 * @KDBUS_ITEM_PIDS:			Process identifiers
 * @KDBUS_ITEM_AUXGROUPS:		Auxiliary process groups
 * @KDBUS_ITEM_OWNED_NAME:		A name owned by the associated
 *					connection
 * @KDBUS_ITEM_TID_COMM:		Thread ID "comm" identifier
 *					(Don't trust this, see below.)
 * @KDBUS_ITEM_PID_COMM:		Process ID "comm" identifier
 *					(Don't trust this, see below.)
 * @KDBUS_ITEM_EXE:			The path of the executable
 *					(Don't trust this, see below.)
 * @KDBUS_ITEM_CMDLINE:			The process command line
 *					(Don't trust this, see below.)
 * @KDBUS_ITEM_CGROUP:			The croup membership
 * @KDBUS_ITEM_CAPS:			The process capabilities
 * @KDBUS_ITEM_SECLABEL:		The security label
 * @KDBUS_ITEM_AUDIT:			The audit IDs
 * @KDBUS_ITEM_CONN_DESCRIPTION:	The connection's human-readable name
 *					(debugging)
 * @_KDBUS_ITEM_POLICY_BASE:		Start of policy items
 * @KDBUS_ITEM_POLICY_ACCESS:		Policy access block
 * @_KDBUS_ITEM_KERNEL_BASE:		Start of kernel-generated message items
 * @KDBUS_ITEM_NAME_ADD:		Notification in kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_REMOVE:		Notification in kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_CHANGE:		Notification in kdbus_notify_name_change
 * @KDBUS_ITEM_ID_ADD:			Notification in kdbus_notify_id_change
 * @KDBUS_ITEM_ID_REMOVE:		Notification in kdbus_notify_id_change
 * @KDBUS_ITEM_REPLY_TIMEOUT:		Timeout has been reached
 * @KDBUS_ITEM_REPLY_DEAD:		Destination died
 *
 * N.B: The process and thread COMM fields, as well as the CMDLINE and
 * EXE fields may be altered by unprivileged processes und should
 * hence *not* used for security decisions. Peers should make use of
 * these items only for informational purposes, such as generating log
 * records.
 */
enum kdbus_item_type {
	_KDBUS_ITEM_NULL,
	_KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_NEGOTIATE = _KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_PAYLOAD_VEC,
	KDBUS_ITEM_PAYLOAD_OFF,
	KDBUS_ITEM_PAYLOAD_MEMFD,
	KDBUS_ITEM_FDS,
	KDBUS_ITEM_CANCEL_FD,
	KDBUS_ITEM_BLOOM_PARAMETER,
	KDBUS_ITEM_BLOOM_FILTER,
	KDBUS_ITEM_BLOOM_MASK,
	KDBUS_ITEM_DST_NAME,
	KDBUS_ITEM_MAKE_NAME,
	KDBUS_ITEM_ATTACH_FLAGS_SEND,
	KDBUS_ITEM_ATTACH_FLAGS_RECV,
	KDBUS_ITEM_ID,
	KDBUS_ITEM_NAME,

	/* keep these item types in sync with KDBUS_ATTACH_* flags */
	_KDBUS_ITEM_ATTACH_BASE = 0x1000,
	KDBUS_ITEM_TIMESTAMP = _KDBUS_ITEM_ATTACH_BASE,
	KDBUS_ITEM_CREDS,
	KDBUS_ITEM_PIDS,
	KDBUS_ITEM_AUXGROUPS,
	KDBUS_ITEM_OWNED_NAME,
	KDBUS_ITEM_TID_COMM,
	KDBUS_ITEM_PID_COMM,
	KDBUS_ITEM_EXE,
	KDBUS_ITEM_CMDLINE,
	KDBUS_ITEM_CGROUP,
	KDBUS_ITEM_CAPS,
	KDBUS_ITEM_SECLABEL,
	KDBUS_ITEM_AUDIT,
	KDBUS_ITEM_CONN_DESCRIPTION,

	_KDBUS_ITEM_POLICY_BASE = 0x2000,
	KDBUS_ITEM_POLICY_ACCESS = _KDBUS_ITEM_POLICY_BASE,

	_KDBUS_ITEM_KERNEL_BASE = 0x8000,
	KDBUS_ITEM_NAME_ADD = _KDBUS_ITEM_KERNEL_BASE,
	KDBUS_ITEM_NAME_REMOVE,
	KDBUS_ITEM_NAME_CHANGE,
	KDBUS_ITEM_ID_ADD,
	KDBUS_ITEM_ID_REMOVE,
	KDBUS_ITEM_REPLY_TIMEOUT,
	KDBUS_ITEM_REPLY_DEAD,
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
