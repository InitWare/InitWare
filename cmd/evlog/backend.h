/*
 *    LICENCE NOTICE
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */
/**
 * SQLite backend.
 */

#ifndef BACKEND_H_
#define BACKEND_H_

#include <sys/types.h>

#include "systemd/sd-id128.h"

#include "time-util.h"

struct sqlite3;
struct sqlite3_stmt;
struct Evlogd;

enum Transport {
	kAudit = 1,
	kDriver = 2,
	kSyslog = 3,
	kJournal = 4,
	kStdout = 5,
	kKernel = 6,
};

struct LogLine {
	dual_timestamp timestamp;

	char *systemd_slice;
	char *systemd_unit;
	char *systemd_user_unit;
	char *systemd_user_slice;
	char *systemd_session;
	uid_t systemd_user_uid;

	pid_t pid;
	uid_t uid;
	gid_t gid;
	char *command;
	char *exe;
	char *cmdline;

	usec_t source_realtime_timestamp;
	sd_id128_t boot_id;
	sd_id128_t machine_id;
	char *hostname;
	enum Transport transport;

	char *message;
	sd_id128_t message_id;
	int priority;
	int syslog_facility;
	char *syslog_identifier;
	char *extra_fields_json;
};

struct Backend {
	/** Connection to the SQLite database. */
	struct sqlite3 *db_conn;
	/** Prepared statement to insert a log line into the database. */
	struct sqlite3_stmt *insert_stmt;
};

typedef enum Transport Transport;
typedef struct LogLine LogLine;
typedef struct Backend Backend;

int backend_init(struct Evlogd *manager, Backend *bend);
int backend_insert(Backend *bend, LogLine *line);

#endif /* BACKEND_H_ */
