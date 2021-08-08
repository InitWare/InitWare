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

#include "sqlite3.h"

#include "evlogd.h"
#include "schema.h"
#include "sink_sqlite.h"
#include "util.h"

#pragma region SQLite extras

#define FMTWRAPPER(fun, ...)                  \
	char *query;                          \
	int res;                              \
	va_list args;                         \
                                              \
	va_start(args, fmt);                  \
                                              \
	if (vasprintf(&query, fmt, args) < 0) \
		return SQLITE_NOMEM;          \
	res = fun(__VA_ARGS__);               \
	printf("QUERY: %s\n", query);         \
	free(query);                          \
                                              \
	va_end(args);                         \
	return res

int sqlite3_execf(sqlite3 *conn, int (*callback)(void *, int, char **, char **), void *arg,
    char **errmsg, const char *fmt, ...)
{
	FMTWRAPPER(sqlite3_exec, conn, query, callback, arg, errmsg);
}

int sqlite3_prepare_v2f(sqlite3 *db, /* Database handle */
    sqlite3_stmt **ppStmt,	     /* OUT: Statement handle */
    const char **pzTail,	     /* OUT: Pointer to unused portion of zSql */
    const char *fmt,		     /* SQL statement, UTF-8 encoded */
    ...)
{
	FMTWRAPPER(sqlite3_prepare_v2, db, query, -1, ppStmt, pzTail);
}

int sqlite3_get_single_int(sqlite3 *conn, int *result, const char *query)
{
	sqlite3_stmt *stmt;
	int res = sqlite3_prepare_v2(conn, query, -1, &stmt, 0);

	if (res != SQLITE_OK)
		goto finish;

	res = sqlite3_step(stmt);

	if (res == SQLITE_ROW)
		*result = sqlite3_column_int(stmt, 0);

finish:
	sqlite3_finalize(stmt);
	return res;
}

int sqlite3_get_single_intf(sqlite3 *conn, int *result, const char *fmt, ...)
{
	char *query;
	int res;
	va_list args;

	va_start(args, fmt);

	if (vasprintf(&query, fmt, args) < 0)
		return SQLITE_NOMEM;
	res = sqlite3_get_single_int(conn, result, query);
	free(query);

	va_end(args);
	return res;
}

#pragma endregion

static const char kInsertSql[] =
    "INSERT INTO 'Events'("
    "'__REALTIME_TIMESTAMP', '__MONOTONIC_TIMESTAMP', "
    "'_SYSTEMD_SLICE', '_SYSTEMD_UNIT', '_SYSTEMD_USER_UNIT', "
    " '_SYSTEMD_USER_SLICE', '_SYSTEMD_SESSION', '_SYSTEMD_OWNER_UID', "
    "'_PID', '_UID', '_GID', '_COMM', '_EXE', '_CMDLINE', "
    "'_SOURCE_REALTIME_TIMESTAMP', '_BOOT_ID', '_MACHINE_ID', '_HOSTNAME', "
    "'_TRANSPORT', "
    "'MESSAGE', 'MESSAGE_ID', 'PRIORITY', 'SYSLOG_FACILITY', "
    "'SYSLOG_IDENTIFIER', 'EXTRA_FIELDS_JSON'"
    ") VALUES ("
    ":realtime_ts, :monotonic_ts, "
    ":slice, :unit, :user_unit, :user_slice, :session, :owner_uid, "
    ":pid, :uid, :gid, :comm, :exe, :cmdline, "
    ":source_realtime_ts, :boot_id, :machine_id, :hostname, :transport, "
    ":message, :message_id, :priority, :syslog_facility, :syslog_identifier, "
    ":extra_json"
    ");";

static void sqlite_log(void *userdata, int errcode, const char *errmsg)
{
	log_warning("SQLite: Code %d, %s\n", errcode, errmsg);
}

/**
 * Get schema version.
 *
 * @retval <0 (negative of SQLite error code) for bad failure
 * @retval 0 for none
 * @retval >0 schema version
 */
static int schema_version(sqlite3 *db)
{
	int ver, r;
	r = sqlite3_get_single_int(db, &ver, "SELECT Version FROM Metadata;");
	if (r == SQLITE_ERROR)
		return 0;
	else if (r != SQLITE_ROW)
		return -r;
	else
		return ver;
}

/** Check integrity of DB. Returns 0 if fine. */
static int check_integrity(sqlite3 *db)
{
	bool integrity = false;
	sqlite3_stmt *stmt = NULL;
	int r;
	const char *result;

	r = sqlite3_prepare_v2(db, "PRAGMA integrity_check;", -1, &stmt, NULL);
	if (r != SQLITE_OK)
		return log_error_errno(EINVAL, "Failed to check integrity: %s\n",
		    sqlite3_errmsg(db));

	r = sqlite3_step(stmt);
	if (r != SQLITE_ROW) {
		log_error("Failed to check integrity: %s\n", sqlite3_errmsg(db));
		r = -EINVAL;
		goto finish;
	}

	result = (const char *) sqlite3_column_text(stmt, 0);
	if (result && streq(result, (const char *) "ok"))
		r = 0;
	else
		r = -EINVAL;

finish:
	sqlite3_finalize(stmt);

	return r;
}

int backend_init(struct Evlogd *manager, Backend *bend)
{
	int r;

	sqlite3_initialize();
	sqlite3_config(SQLITE_CONFIG_LOG, sqlite_log, bend);

	r = sqlite3_open_v2(DATABASE, &bend->db_conn,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
	if (r != SQLITE_OK)
		return log_error_errno(EIO, "Failed to create or open event log database (%s): %s\n",
		    DATABASE, sqlite3_errmsg(bend->db_conn));

	r = check_integrity(bend->db_conn);
	if (r < 0)
		return r;

	r = schema_version(bend->db_conn);
	if (r < 0)
		return log_error_errno(EIO, "Database corrupt: %s\n", sqlite3_errmsg(bend->db_conn));
	if (r == 0) {
		log_debug("Setting up schema for empty database.\n");

		r = sqlite3_exec(bend->db_conn, kschema_sql, NULL, NULL, NULL);
		if (r != SQLITE_OK)
			goto fail;

		r = sqlite3_exec(bend->db_conn, "INSERT INTO 'Metadata' VALUES (1);", NULL, NULL,
		    NULL);

		/* fall-through */
	fail:
		if (r != SQLITE_OK)
			return log_error_errno(EIO, "Failed to set up database schema: %s\n",
			    sqlite3_errmsg(bend->db_conn));
	} else
		log_debug("Database schema version is %d.\n", r);

	r = sqlite3_prepare_v2(bend->db_conn, kInsertSql, -1, &bend->insert_stmt, NULL);
	if (r != SQLITE_OK)
		return log_error_errno(EIO, "Failed to set up prepared statements: %s\n",
		    sqlite3_errmsg(bend->db_conn));

	return 0;
}

void backend_shutdown(Backend *bend)
{
	sqlite3_finalize(bend->insert_stmt);
	sqlite3_close(bend->db_conn);
}

int backend_insert(Backend *bend, LogLine *line)
{
	int r;
	bool has_message_id = false;
	char boot_id[33], machine_id[33], message_id[33];

	sd_id128_to_string(line->boot_id, boot_id);
	sd_id128_to_string(line->machine_id, machine_id);
	printf("Machid: %s. Bootid: %s.\n", machine_id, boot_id);
	if (line->message_id.qwords[0] != 0 && line->message_id.qwords[1] != 0) {
		/* if message_id is 0, we don't include it */
		has_message_id = true;
		sd_id128_to_string(line->message_id, message_id);
	}

#define CHECK_FAIL                                                   \
	if (r != SQLITE_OK) {                                        \
		log_error("Failed to bind prepared statement: %s\n", \
		    sqlite3_errmsg(bend->db_conn));                  \
		r = -EIO;                                            \
		goto finish;                                         \
	}
#define BIND_I64_NEG1_NULL(index, val)                                 \
	if (val == -1)                                                 \
		r = sqlite3_bind_null(bend->insert_stmt, index);       \
	else                                                           \
		r = sqlite3_bind_int64(bend->insert_stmt, index, val); \
	CHECK_FAIL
#define BIND_I64(index, val)                                   \
	r = sqlite3_bind_int64(bend->insert_stmt, index, val); \
	CHECK_FAIL
#define BIND_STR(index, val)                                                     \
	r = sqlite3_bind_text(bend->insert_stmt, index, val, -1, SQLITE_STATIC); \
	CHECK_FAIL

	BIND_I64(1, line->timestamp.realtime);
	BIND_I64(2, line->timestamp.monotonic);

	BIND_STR(3, line->metadata.systemd_slice);
	BIND_STR(4, line->metadata.systemd_unit);
	BIND_STR(5, line->metadata.systemd_user_unit);
	BIND_STR(6, line->metadata.systemd_user_slice);
	BIND_STR(7, line->metadata.systemd_session);
	BIND_I64_NEG1_NULL(8, line->metadata.systemd_user_uid);

	BIND_I64_NEG1_NULL(9, line->metadata.cred.pid);
	BIND_I64_NEG1_NULL(10, line->metadata.cred.uid);
	BIND_I64_NEG1_NULL(11, line->metadata.cred.gid);
	BIND_STR(12, line->metadata.command);
	BIND_STR(13, line->metadata.exe);
	BIND_STR(14, line->metadata.cmdline);

	BIND_I64_NEG1_NULL(15, line->source_realtime_timestamp);
	BIND_STR(16, boot_id);
	BIND_STR(17, machine_id);
	BIND_STR(18, line->hostname);
	BIND_I64(19, line->transport);

	BIND_STR(20, line->message);
	if (has_message_id) {
		BIND_STR(21, message_id);
	} else
		sqlite3_bind_null(bend->insert_stmt, 21);
	BIND_I64(22, line->priority);
	BIND_I64_NEG1_NULL(23, line->syslog_facility);
	BIND_STR(24, line->syslog_identifier);
	BIND_STR(25, line->extra_fields_json);

	r = sqlite3_step(bend->insert_stmt);
	if (r != SQLITE_DONE) {
		log_error("Failed to execute prepared statement: %s\n",
		    sqlite3_errmsg(bend->db_conn));
		r = -EIO;
	}

finish:
	sqlite3_reset(bend->insert_stmt);
	return r;
}