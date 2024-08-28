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

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

#include "acl-util.h"
#include "alloc-util.h"
#include "audit.h"
#include "bsdsigfd.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "console.h"
#include "fileio.h"
#include "hashmap.h"
#include "journal-authenticate.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "kmsg.h"
#include "list.h"
#include "missing.h"
#include "mkdir.h"
#include "native.h"
#include "rate-limit.h"
#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-messages.h"
#include "selinux-util.h"
#include "server.h"
#include "socket-util.h"
#include "stream.h"
#include "syslog_in.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifdef SVC_PLATFORM_Linux
#include <linux/sockios.h>
#endif

#ifdef SVC_USE_libudev
#include <libudev.h>
#endif

#define USER_JOURNALS_MAX 1024

#define DEFAULT_SYNC_INTERVAL_USEC (5 * USEC_PER_MINUTE)
#define DEFAULT_RATE_LIMIT_INTERVAL (30 * USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 1000
#define DEFAULT_MAX_FILE_USEC USEC_PER_MONTH

#define RECHECK_AVAILABLE_SPACE_USEC (30 * USEC_PER_SEC)

#define NOTIFY_SNDBUF_SIZE (8 * 1024 * 1024)

/* Pick a good default that is likely to fit into AF_UNIX and AF_INET SOCK_DGRAM datagrams, and even leaves some room
+ * for a bit of additional metadata. */
#define DEFAULT_LINE_MAX (48 * 1024)

static const char *const storage_table[_STORAGE_MAX] = { [STORAGE_AUTO] =
								 "auto",
	[STORAGE_VOLATILE] = "volatile",
	[STORAGE_PERSISTENT] = "persistent",
	[STORAGE_NONE] = "none" };

DEFINE_STRING_TABLE_LOOKUP(storage, Storage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_storage, storage, Storage,
	"Failed to parse storage setting");

static const char *const split_mode_table[_SPLIT_MAX] = {
	[SPLIT_LOGIN] = "login",
	[SPLIT_UID] = "uid",
	[SPLIT_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(split_mode, SplitMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_split_mode, split_mode, SplitMode,
	"Failed to parse split mode setting");

int
config_parse_line_max(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	size_t *sz = data;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	if (isempty(rvalue))
		/* Empty assignment means default */
		*sz = DEFAULT_LINE_MAX;
	else {
		uint64_t v;
		off_t u;

		r = parse_size(rvalue, 1024, &u);
		if (r < 0) {
			log_syntax(unit, LOG_ERR, filename, line, r,
				"Failed to parse LineMax= value, ignoring: %s",
				rvalue);
			return 0;
		}

		/* Backport note */
		/* Upstream ditched use of off_t however our parse_size implementation still takes off_t*
                 * as an argument. Since we compile with -Werror, we have two choices, either disable sign-compare
                 * warning or do this casting so we don't have to change rest of the code. I think it is
                 * better to do cast here instead of rewriting the code so it deals with off_t instead of
                 * uint64_t. Doing conversion off_t -> uint64_t is something that we should think about. */
		v = (uint64_t)u;

		if (v < 79) {
			/* Why specify 79 here as minimum line length? Simply, because the most common traditional
                         * terminal size is 80ch, and it might make sense to break one character before the natural
                         * line break would occur on that. */
			log_syntax(unit, LOG_WARNING, filename, line, 0,
				"LineMax= too small, clamping to 79: %s",
				rvalue);
			*sz = 79;
		} else if (v > (uint64_t)(SSIZE_MAX - 1)) {
			/* So, why specify SSIZE_MAX-1 here? Because that's one below the largest size value read()
                         * can return, and we need one extra byte for the trailing NUL byte. Of course IRL such large
                         * memory allocations will fail anyway, hence this limit is mostly theoretical anyway, as we'll
                         * fail much earlier anyway. */
			log_syntax(unit, LOG_WARNING, filename, line, 0,
				"LineMax= too large, clamping to %" PRIu64
				": %s",
				(uint64_t)(SSIZE_MAX - 1), rvalue);
			*sz = SSIZE_MAX - 1;
		} else
			*sz = (size_t)v;
	}

	return 0;
}

static uint64_t
available_space(Server *s, bool verbose)
{
	char ids[33];
	_cleanup_free_ char *p = NULL;
	sd_id128_t machine;
	struct statvfs ss;
	uint64_t sum = 0, ss_avail = 0, avail = 0;
	int r;
	_cleanup_closedir_ DIR *d = NULL;
	usec_t ts;
	const char *f;
	JournalMetrics *m;

	ts = now(CLOCK_MONOTONIC);

	if (s->cached_available_space_timestamp + RECHECK_AVAILABLE_SPACE_USEC >
			ts &&
		!verbose)
		return s->cached_available_space;

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return 0;

	if (s->system_journal) {
		f = SVC_PERSISTENTLOGDIR "/";
		m = &s->system_metrics;
	} else {
		f = SVC_RUNTIMELOGDIR "/";
		m = &s->runtime_metrics;
	}

	assert(m);

	p = strappend(f, sd_id128_to_string(machine, ids));
	if (!p)
		return 0;

	d = opendir(p);
	if (!d)
		return 0;

	if (fstatvfs(dirfd(d), &ss) < 0)
		return 0;

	for (;;) {
		struct stat st;
		struct dirent *de;

		errno = 0;
		de = readdir(d);
		if (!de && errno != 0)
			return 0;

		if (!de)
			break;

		if (!endswith(de->d_name, ".journal") &&
			!endswith(de->d_name, ".journal~"))
			continue;

		if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
			continue;

		if (!S_ISREG(st.st_mode))
			continue;

		sum += (uint64_t)st.st_blocks * 512UL;
	}

	ss_avail = ss.f_bsize * ss.f_bavail;

	/* If we reached a high mark, we will always allow this much
         * again, unless usage goes above max_use. This watermark
         * value is cached so that we don't give up space on pressure,
         * but hover below the maximum usage. */

	if (m->use < sum)
		m->use = sum;

	avail = LESS_BY(ss_avail, m->keep_free);

	s->cached_available_space = LESS_BY(MIN(m->max_use, avail), sum);
	s->cached_available_space_timestamp = ts;

	if (verbose) {
		char fb1[FORMAT_BYTES_MAX], fb2[FORMAT_BYTES_MAX],
			fb3[FORMAT_BYTES_MAX], fb4[FORMAT_BYTES_MAX],
			fb5[FORMAT_BYTES_MAX];

		server_driver_message(s, SD_MESSAGE_JOURNAL_USAGE,
			"%s journal is using %s (max allowed %s, "
			"trying to leave %s free of %s available → current limit %s).",
			s->system_journal ? "Permanent" : "Runtime",
			format_bytes(fb1, sizeof(fb1), sum),
			format_bytes(fb2, sizeof(fb2), m->max_use),
			format_bytes(fb3, sizeof(fb3), m->keep_free),
			format_bytes(fb4, sizeof(fb4), ss_avail),
			format_bytes(fb5, sizeof(fb5),
				s->cached_available_space + sum));
	}

	return s->cached_available_space;
}

void
server_fix_perms(Server *s, JournalFile *f, uid_t uid)
{
	int r;
#ifdef HAVE_ACL
	acl_t acl;
	acl_entry_t entry;
	acl_permset_t permset;
#endif

	assert(f);

	r = fchmod(f->fd, 0640);
	if (r < 0)
		log_warning_errno(r,
			"Failed to fix access mode on %s, ignoring: %m",
			f->path);

#ifdef HAVE_ACL
	if (uid <= SYSTEM_UID_MAX)
		return;

	acl = acl_get_fd(f->fd);
	if (!acl) {
		log_warning_errno(errno,
			"Failed to read ACL on %s, ignoring: %m", f->path);
		return;
	}

	r = acl_find_uid(acl, uid, &entry);
	if (r <= 0) {
		if (acl_create_entry(&acl, &entry) < 0 ||
			acl_set_tag_type(entry, ACL_USER) < 0 ||
			acl_set_qualifier(entry, &uid) < 0) {
			log_warning_errno(errno,
				"Failed to patch ACL on %s, ignoring: %m",
				f->path);
			goto finish;
		}
	}

	/* We do not recalculate the mask unconditionally here,
         * so that the fchmod() mask above stays intact. */
	if (acl_get_permset(entry, &permset) < 0 ||
		acl_add_perm(permset, ACL_READ) < 0 ||
		calc_acl_mask_if_needed(&acl) < 0) {
		log_warning_errno(errno,
			"Failed to patch ACL on %s, ignoring: %m", f->path);
		goto finish;
	}

	if (acl_set_fd(f->fd, acl) < 0)
		log_warning_errno(errno,
			"Failed to set ACL on %s, ignoring: %m", f->path);

finish:
	acl_free(acl);
#endif
}

static bool
flushed_flag_is_set(void)
{
	return access(SVC_PKGRUNSTATEDIR "/journal/flushed", F_OK) >= 0;
}

static int
system_journal_open(Server *s, bool flush_requested, bool verbose)
{
	int r;
	char *fn;
	sd_id128_t machine;
	char ids[33];

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return log_error_errno(r, "Failed to get machine id: %m");

	if (!s->system_journal &&
		IN_SET(s->storage, STORAGE_PERSISTENT, STORAGE_AUTO) &&
		(flush_requested || flushed_flag_is_set())) {
		sd_id128_to_string(machine, ids);

		/* If in auto mode: first try to create the machine
                 * path, but not the prefix.
                 *
                 * If in persistent mode: create /var/log/journal and
                 * the machine path */

		if (s->storage == STORAGE_PERSISTENT)
			(void)mkdir_p(SVC_PERSISTENTLOGDIR "/", 0755);

		fn = strjoina(SVC_PERSISTENTLOGDIR "/", ids);
		(void)mkdir(fn, 0755);

		fn = strjoina(fn, "/system.journal");
		r = journal_file_open_reliably(fn, O_RDWR | O_CREAT, 0640,
			s->compress, s->seal, &s->system_metrics, s->mmap, NULL,
			&s->system_journal);

		if (r >= 0) {
			server_fix_perms(s, s->system_journal, 0);
			available_space(s, verbose);
		} else {
			if (r != -ENOENT && r != -EROFS)
				log_warning_errno(r,
					"Failed to open system journal: %m");

			r = 0;
		}

		/* If the runtime journal is open, and we're post-flush, we're
                 * recovering from a failed system journal rotate (ENOSPC)
                 * for which the runtime journal was reopened.
                 *
                 * Perform an implicit flush to var, leaving the runtime
                 * journal closed, now that the system journal is back.
                 */
		if (!flush_requested)
			(void)server_flush_to_var(s, true);
	}

	if (!s->runtime_journal && (s->storage != STORAGE_NONE)) {
		sd_id128_to_string(machine, ids);

		fn = strjoin(SVC_RUNTIMELOGDIR "/", ids, "/system.journal",
			NULL);
		if (!fn)
			return -ENOMEM;

		if (s->system_journal) {
			/* Try to open the runtime journal, but only
                         * if it already exists, so that we can flush
                         * it into the system journal */

			r = journal_file_open(fn, O_RDWR, 0640, s->compress,
				false, &s->runtime_metrics, s->mmap, NULL,
				&s->runtime_journal);
			free(fn);

			if (r < 0) {
				if (r != -ENOENT)
					log_warning_errno(r,
						"Failed to open runtime journal: %m");

				r = 0;
			}

		} else {
			/* OK, we really need the runtime journal, so create
                         * it if necessary. */

			(void)mkdir_p(SVC_RUNTIMELOGDIR, 0755);
			(void)mkdir_parents(fn, 0750);

			r = journal_file_open_reliably(fn, O_RDWR | O_CREAT,
				0640, s->compress, false, &s->runtime_metrics,
				s->mmap, NULL, &s->runtime_journal);
			free(fn);

			if (r < 0)
				return log_error_errno(r,
					"Failed to open runtime journal: %m");
		}

		if (s->runtime_journal) {
			server_fix_perms(s, s->runtime_journal, 0);
			available_space(s, verbose);
		}
	}

	return r;
}

static JournalFile *
find_journal(Server *s, uid_t uid)
{
	_cleanup_free_ char *p = NULL;
	int r;
	JournalFile *f;
	sd_id128_t machine;

	assert(s);

	/* A rotate that fails to create the new journal (ENOSPC) leaves the
         * rotated journal as NULL.  Unless we revisit opening, even after
         * space is made available we'll continue to return NULL indefinitely.
         *
         * system_journal_open() is a noop if the journals are already open, so
         * we can just call it here to recover from failed rotates (or anything
         * else that's left the journals as NULL).
         *
         * Fixes https://github.com/systemd/systemd/issues/3968 */
	(void)system_journal_open(s, false, false);

	/* We split up user logs only on /var, not on /run. If the
         * runtime file is open, we write to it exclusively, in order
         * to guarantee proper order as soon as we flush /run to
         * /var and close the runtime file. */

	if (s->runtime_journal)
		return s->runtime_journal;

#ifndef SYSTEM_UID_MAX
#define SYSTEM_UID_MAX 99
#endif
	if (uid <= SYSTEM_UID_MAX)
		return s->system_journal;

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return s->system_journal;

	f = ordered_hashmap_get(s->user_journals, UINT32_TO_PTR(uid));
	if (f)
		return f;

	if (asprintf(&p,
		    SVC_PERSISTENTLOGDIR "/" SD_ID128_FORMAT_STR
					 "/user-" UID_FMT ".journal",
		    SD_ID128_FORMAT_VAL(machine), uid) < 0)
		return s->system_journal;

	while (ordered_hashmap_size(s->user_journals) >= USER_JOURNALS_MAX) {
		/* Too many open? Then let's close one */
		f = ordered_hashmap_steal_first(s->user_journals);
		assert(f);
		journal_file_close(f);
	}

	r = journal_file_open_reliably(p, O_RDWR | O_CREAT, 0640, s->compress,
		s->seal, &s->system_metrics, s->mmap, NULL, &f);
	if (r < 0)
		return s->system_journal;

	server_fix_perms(s, f, uid);

	r = ordered_hashmap_put(s->user_journals, UINT32_TO_PTR(uid), f);
	if (r < 0) {
		journal_file_close(f);
		return s->system_journal;
	}

	return f;
}

static int
do_rotate(Server *s, JournalFile **f, const char *name, bool seal, uint32_t uid)
{
	int r;
	assert(s);

	if (!*f)
		return -EINVAL;

	r = journal_file_rotate(f, s->compress, seal);
	if (r < 0)
		if (*f)
			log_error_errno(r, "Failed to rotate %s: %m",
				(*f)->path);
		else
			log_error_errno(r,
				"Failed to create new %s journal: %m", name);
	else
		server_fix_perms(s, *f, uid);

	return r;
}

void
server_rotate(Server *s)
{
	JournalFile *f;
	void *k;
	Iterator i;
	int r;

	log_debug("Rotating...");

	do_rotate(s, &s->runtime_journal, "runtime", false, 0);
	do_rotate(s, &s->system_journal, "system", s->seal, 0);

	ORDERED_HASHMAP_FOREACH_KEY (f, k, s->user_journals, i) {
		r = do_rotate(s, &f, "user", s->seal, PTR_TO_UINT32(k));
		if (r >= 0)
			ordered_hashmap_replace(s->user_journals, k, f);
		else if (!f)
			/* Old file has been closed and deallocated */
			ordered_hashmap_remove(s->user_journals, k);
	}
}

void
server_sync(Server *s)
{
	JournalFile *f;
	void *k;
	Iterator i;
	int r;

	if (s->system_journal) {
		r = journal_file_set_offline(s->system_journal);
		if (r < 0)
			log_error_errno(r, "Failed to sync system journal: %m");
	}

	ORDERED_HASHMAP_FOREACH_KEY (f, k, s->user_journals, i) {
		r = journal_file_set_offline(f);
		if (r < 0)
			log_error_errno(r, "Failed to sync user journal: %m");
	}

	if (s->sync_event_source) {
		r = sd_event_source_set_enabled(s->sync_event_source,
			SD_EVENT_OFF);
		if (r < 0)
			log_error_errno(r,
				"Failed to disable sync timer source: %m");
	}

	s->sync_scheduled = false;
}

static void
do_vacuum(Server *s, const char *id, JournalFile *f, const char *path,
	JournalMetrics *metrics)
{
	uint64_t total, limit = metrics->max_use;
	struct statvfs st;
	const char *p;
	int r;

	if (!f)
		return;

	p = strjoina(path, id);

	r = statvfs(p, &st);
	if (r < 0) {
		log_error_errno(r, "Failed to statvfs: %s", p);
		return;
	}

	total = st.f_bsize * st.f_blocks;
	if (total - metrics->keep_free < limit)
		limit = total - metrics->keep_free;

	r = journal_directory_vacuum(p, limit, s->max_retention_usec,
		&s->oldest_file_usec, false);
	if (r < 0 && r != -ENOENT)
		log_error_errno(r, "Failed to vacuum %s: %m", p);
}

void
server_vacuum(Server *s)
{
	char ids[33];
	sd_id128_t machine;
	int r;

	log_debug("Vacuuming...");

	s->oldest_file_usec = 0;

	r = sd_id128_get_machine(&machine);
	if (r < 0) {
		log_error_errno(r, "Failed to get machine ID: %m");
		return;
	}
	sd_id128_to_string(machine, ids);

	do_vacuum(s, ids, s->system_journal, SVC_PERSISTENTLOGDIR "/",
		&s->system_metrics);
	do_vacuum(s, ids, s->runtime_journal, SVC_RUNTIMELOGDIR "/",
		&s->runtime_metrics);

	s->cached_available_space_timestamp = 0;
}

static void
server_cache_machine_id(Server *s)
{
	sd_id128_t id;
	int r;

	assert(s);

	r = sd_id128_get_machine(&id);
	if (r < 0)
		return;

	sd_id128_to_string(id, stpcpy(s->machine_id_field, "_MACHINE_ID="));
}

static void
server_cache_boot_id(Server *s)
{
	sd_id128_t id;
	int r;

	assert(s);

	r = sd_id128_get_boot(&id);
	if (r < 0)
		return;

	sd_id128_to_string(id, stpcpy(s->boot_id_field, "_BOOT_ID="));
}

static void
server_cache_hostname(Server *s)
{
	_cleanup_free_ char *t = NULL;
	char *x;

	assert(s);

	t = gethostname_malloc();
	if (!t)
		return;

	x = strappend("_HOSTNAME=", t);
	if (!x)
		return;

	free(s->hostname_field);
	s->hostname_field = x;
}

static bool
shall_try_append_again(JournalFile *f, int r)
{
	/* -E2BIG            Hit configured limit
           -EFBIG            Hit fs limit
           -EDQUOT           Quota limit hit
           -ENOSPC           Disk full
           -EIO              I/O error of some kind (mmap)
           -EHOSTDOWN        Other machine
           -EBUSY            Unclean shutdown
           -EPROTONOSUPPORT  Unsupported feature
           -EBADMSG          Corrupted
           -ENODATA          Truncated
           -ESHUTDOWN        Already archived
           -EIDRM            Journal file has been deleted */

	if (r == -E2BIG || r == -EFBIG || r == -EDQUOT || r == -ENOSPC)
		log_debug("%s: Allocation limit reached, rotating.", f->path);
	else if (r == -EHOSTDOWN)
		log_info("%s: Journal file from other machine, rotating.",
			f->path);
	else if (r == -EBUSY)
		log_info("%s: Unclean shutdown, rotating.", f->path);
	else if (r == -EPROTONOSUPPORT)
		log_info("%s: Unsupported feature, rotating.", f->path);
	else if (r == -EBADMSG || r == -ENODATA || r == ESHUTDOWN)
		log_warning("%s: Journal file corrupted, rotating.", f->path);
	else if (r == -EIO)
		log_warning("%s: IO error, rotating.", f->path);
	else if (r == -EIDRM)
		log_warning("%s: Journal file has been deleted, rotating.",
			f->path);
	else
		return false;

	return true;
}

static void
write_to_journal(Server *s, uid_t uid, struct iovec *iovec, unsigned n,
	int priority)
{
	JournalFile *f;
	bool vacuumed = false;
	int r;

	assert(s);
	assert(iovec);
	assert(n > 0);

	f = find_journal(s, uid);
	if (!f)
		return;

	if (journal_file_rotate_suggested(f, s->max_file_usec)) {
		log_debug(
			"%s: Journal header limits reached or header out-of-date, rotating.",
			f->path);
		server_rotate(s);
		server_vacuum(s);
		vacuumed = true;

		f = find_journal(s, uid);
		if (!f)
			return;
	}

	r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL,
		NULL);
	if (r >= 0) {
		server_schedule_sync(s, priority);
		return;
	}

	if (vacuumed || !shall_try_append_again(f, r)) {
		log_error_errno(r,
			"Failed to write entry (%d items, %zu bytes), ignoring: %m",
			n, IOVEC_TOTAL_SIZE(iovec, n));
		return;
	}

	server_rotate(s);
	server_vacuum(s);

	f = find_journal(s, uid);
	if (!f)
		return;

	log_debug("Retrying write.");
	r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL,
		NULL);
	if (r < 0)
		log_error_errno(r,
			"Failed to write entry (%d items, %zu bytes) despite vacuuming, ignoring: %m",
			n, IOVEC_TOTAL_SIZE(iovec, n));
	else
		server_schedule_sync(s, priority);
}

static void
dispatch_message_real(Server *s, struct iovec *iovec, unsigned n, unsigned m,
	const struct socket_ucred *ucred, const struct timeval *tv,
	const char *label, size_t label_len, const char *unit_id, int priority,
	pid_t object_pid)
{
	char pid[sizeof("_PID=") + DECIMAL_STR_MAX(pid_t)],
		uid[sizeof("_UID=") + DECIMAL_STR_MAX(uid_t)],
		gid[sizeof("_GID=") + DECIMAL_STR_MAX(gid_t)],
		owner_uid[sizeof("_SYSTEMD_OWNER_UID=") +
			DECIMAL_STR_MAX(uid_t)],
		source_time[sizeof("_SOURCE_REALTIME_TIMESTAMP=") +
			DECIMAL_STR_MAX(usec_t)],
		o_uid[sizeof("OBJECT_UID=") + DECIMAL_STR_MAX(uid_t)],
		o_gid[sizeof("OBJECT_GID=") + DECIMAL_STR_MAX(gid_t)],
		o_owner_uid[sizeof("OBJECT_SYSTEMD_OWNER_UID=") +
			DECIMAL_STR_MAX(uid_t)];
	_cleanup_free_ char *cmdline1 = NULL, *cmdline2 = NULL;
	uid_t object_uid;
	gid_t object_gid;
	char *x;
	int r;
	char *t, *c;
	uid_t realuid = 0, owner = 0, journal_uid;
	bool owner_valid = false;
#ifdef HAVE_AUDIT
	char audit_session[sizeof("_AUDIT_SESSION=") +
		DECIMAL_STR_MAX(uint32_t)],
		audit_loginuid[sizeof("_AUDIT_LOGINUID=") +
			DECIMAL_STR_MAX(uid_t)],
		o_audit_session[sizeof("OBJECT_AUDIT_SESSION=") +
			DECIMAL_STR_MAX(uint32_t)],
		o_audit_loginuid[sizeof("OBJECT_AUDIT_LOGINUID=") +
			DECIMAL_STR_MAX(uid_t)];

	uint32_t audit;
	uid_t loginuid;
#endif

	assert(s);
	assert(iovec);
	assert(n > 0);
	assert(n + N_IOVEC_META_FIELDS +
			(object_pid ? N_IOVEC_OBJECT_FIELDS : 0) <=
		m);

	if (ucred) {
		realuid = ucred->uid;

		sprintf(pid, "_PID=" PID_FMT, ucred->pid);
		IOVEC_SET_STRING(iovec[n++], pid);

		sprintf(uid, "_UID=" UID_FMT, ucred->uid);
		IOVEC_SET_STRING(iovec[n++], uid);

		sprintf(gid, "_GID=" GID_FMT, ucred->gid);
		IOVEC_SET_STRING(iovec[n++], gid);

		r = get_process_comm(ucred->pid, &t);
		if (r >= 0) {
			x = strjoina("_COMM=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_exe(ucred->pid, &t);
		if (r >= 0) {
			x = strjoina("_EXE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_cmdline(ucred->pid, 0, false, &t);
		if (r >= 0) {
			/* At most _SC_ARG_MAX (2MB usually), which is too much to put on stack.
                         * Let's use a heap allocation for this one. */
			cmdline1 = set_iovec_field_free(iovec, &n,
				"_CMDLINE=", t);
		}

		r = get_process_capeff(ucred->pid, &t);
		if (r >= 0) {
			x = strjoina("_CAP_EFFECTIVE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

#ifdef HAVE_AUDIT
		r = audit_session_from_pid(ucred->pid, &audit);
		if (r >= 0) {
			sprintf(audit_session, "_AUDIT_SESSION=%" PRIu32,
				audit);
			IOVEC_SET_STRING(iovec[n++], audit_session);
		}

		r = audit_loginuid_from_pid(ucred->pid, &loginuid);
		if (r >= 0) {
			sprintf(audit_loginuid, "_AUDIT_LOGINUID=" UID_FMT,
				loginuid);
			IOVEC_SET_STRING(iovec[n++], audit_loginuid);
		}
#endif

		r = cg_pid_get_path_shifted(ucred->pid, s->cgroup_root, &c);
		if (r >= 0) {
			char *session = NULL;

			x = strjoina("_SYSTEMD_CGROUP=", c);
			IOVEC_SET_STRING(iovec[n++], x);

			r = cg_path_get_session(c, &t);
			if (r >= 0) {
				session = strjoina("_SYSTEMD_SESSION=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], session);
			}

			if (cg_path_get_owner_uid(c, &owner) >= 0) {
				owner_valid = true;

				sprintf(owner_uid,
					"_SYSTEMD_OWNER_UID=" UID_FMT, owner);
				IOVEC_SET_STRING(iovec[n++], owner_uid);
			}

			if (cg_path_get_unit(c, &t) >= 0) {
				x = strjoina("_SYSTEMD_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			} else if (unit_id && !session) {
				x = strjoina("_SYSTEMD_UNIT=", unit_id);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_user_unit(c, &t) >= 0) {
				x = strjoina("_SYSTEMD_USER_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			} else if (unit_id && session) {
				x = strjoina("_SYSTEMD_USER_UNIT=", unit_id);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_slice(c, &t) >= 0) {
				x = strjoina("_SYSTEMD_SLICE=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			free(c);
		} else if (unit_id) {
			x = strjoina("_SYSTEMD_UNIT=", unit_id);
			IOVEC_SET_STRING(iovec[n++], x);
		}

#ifdef HAVE_SELINUX
		if (mac_selinux_use()) {
			if (label) {
				x = alloca(strlen("_SELINUX_CONTEXT=") +
					label_len + 1);

				*((char *)mempcpy(stpcpy(x,
							  "_SELINUX_CONTEXT="),
					label, label_len)) = 0;
				IOVEC_SET_STRING(iovec[n++], x);
			} else {
				security_context_t con;

				if (getpidcon(ucred->pid, &con) >= 0) {
					x = strjoina("_SELINUX_CONTEXT=", con);

					freecon(con);
					IOVEC_SET_STRING(iovec[n++], x);
				}
			}
		}
#endif
	}
	assert(n <= m);

	if (object_pid) {
		r = get_process_uid(object_pid, &object_uid);
		if (r >= 0) {
			sprintf(o_uid, "OBJECT_UID=" UID_FMT, object_uid);
			IOVEC_SET_STRING(iovec[n++], o_uid);
		}

		r = get_process_gid(object_pid, &object_gid);
		if (r >= 0) {
			sprintf(o_gid, "OBJECT_GID=" GID_FMT, object_gid);
			IOVEC_SET_STRING(iovec[n++], o_gid);
		}

		r = get_process_comm(object_pid, &t);
		if (r >= 0) {
			x = strjoina("OBJECT_COMM=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_exe(object_pid, &t);
		if (r >= 0) {
			x = strjoina("OBJECT_EXE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_cmdline(object_pid, 0, false, &t);
		if (r >= 0)
			cmdline2 = set_iovec_field_free(iovec, &n,
				"OBJECT_CMDLINE=", t);

#ifdef HAVE_AUDIT
		r = audit_session_from_pid(object_pid, &audit);
		if (r >= 0) {
			sprintf(o_audit_session,
				"OBJECT_AUDIT_SESSION=%" PRIu32, audit);
			IOVEC_SET_STRING(iovec[n++], o_audit_session);
		}

		r = audit_loginuid_from_pid(object_pid, &loginuid);
		if (r >= 0) {
			sprintf(o_audit_loginuid,
				"OBJECT_AUDIT_LOGINUID=" UID_FMT, loginuid);
			IOVEC_SET_STRING(iovec[n++], o_audit_loginuid);
		}
#endif

		r = cg_pid_get_path_shifted(object_pid, s->cgroup_root, &c);
		if (r >= 0) {
			x = strjoina("OBJECT_SYSTEMD_CGROUP=", c);
			IOVEC_SET_STRING(iovec[n++], x);

			r = cg_path_get_session(c, &t);
			if (r >= 0) {
				x = strjoina("OBJECT_SYSTEMD_SESSION=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_owner_uid(c, &owner) >= 0) {
				sprintf(o_owner_uid,
					"OBJECT_SYSTEMD_OWNER_UID=" UID_FMT,
					owner);
				IOVEC_SET_STRING(iovec[n++], o_owner_uid);
			}

			if (cg_path_get_unit(c, &t) >= 0) {
				x = strjoina("OBJECT_SYSTEMD_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_user_unit(c, &t) >= 0) {
				x = strjoina("OBJECT_SYSTEMD_USER_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			free(c);
		}
	}
	assert(n <= m);

	if (tv) {
		sprintf(source_time, "_SOURCE_REALTIME_TIMESTAMP=%llu",
			(unsigned long long)timeval_load(tv));
		IOVEC_SET_STRING(iovec[n++], source_time);
	}

	/* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
	if (!isempty(s->boot_id_field))
		IOVEC_SET_STRING(iovec[n++], s->boot_id_field);

	if (!isempty(s->machine_id_field))
		IOVEC_SET_STRING(iovec[n++], s->machine_id_field);

	if (!isempty(s->hostname_field))
		IOVEC_SET_STRING(iovec[n++], s->hostname_field);

	assert(n <= m);

	if (s->split_mode == SPLIT_UID && realuid > 0)
		/* Split up strictly by any UID */
		journal_uid = realuid;
	else if (s->split_mode == SPLIT_LOGIN && realuid > 0 && owner_valid &&
		owner > 0)
		/* Split up by login UIDs.  We do this only if the
                 * realuid is not root, in order not to accidentally
                 * leak privileged information to the user that is
                 * logged by a privileged process that is part of an
                 * unprivileged session. */
		journal_uid = owner;
	else
		journal_uid = 0;

	write_to_journal(s, journal_uid, iovec, n, priority);
}

void
server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...)
{
	char mid[11 + 32 + 1];
	char buffer[16 + LINE_MAX + 1];
	struct iovec iovec[N_IOVEC_META_FIELDS + 4];
	int n = 0;
	va_list ap;
	struct socket_ucred ucred = {};

	assert(s);
	assert(format);

	IOVEC_SET_STRING(iovec[n++], "PRIORITY=6");
	IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=driver");

	memcpy(buffer, "MESSAGE=", 8);
	va_start(ap, format);
	vsnprintf(buffer + 8, sizeof(buffer) - 8, format, ap);
	va_end(ap);
	IOVEC_SET_STRING(iovec[n++], buffer);

	if (!sd_id128_equal(message_id, SD_ID128_NULL)) {
		snprintf(mid, sizeof(mid), LOG_MESSAGE_ID(message_id));
		IOVEC_SET_STRING(iovec[n++], mid);
	}

	ucred.pid = getpid();
	ucred.uid = getuid();
	ucred.gid = getgid();

	dispatch_message_real(s, iovec, n, ELEMENTSOF(iovec), &ucred, NULL,
		NULL, 0, NULL, LOG_INFO, 0);
}

void
server_dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m,
	const struct socket_ucred *ucred, const struct timeval *tv,
	const char *label, size_t label_len, const char *unit_id, int priority,
	pid_t object_pid)
{
	int rl, r;
	_cleanup_free_ char *path = NULL;
	char *c;

	assert(s);
	assert(iovec || n == 0);

	if (n == 0)
		return;

	if (LOG_PRI(priority) > s->max_level_store)
		return;

	/* Stop early in case the information will not be stored
         * in a journal. */
	if (s->storage == STORAGE_NONE)
		return;

	if (!ucred)
		goto finish;

	r = cg_pid_get_path_shifted(ucred->pid, s->cgroup_root, &path);
	if (r < 0)
		goto finish;

	/* example: /user/lennart/3/foobar
         *          /system/dbus.service/foobar
         *
         * So let's cut of everything past the third /, since that is
         * where user directories start */

	c = strchr(path, '/');
	if (c) {
		c = strchr(c + 1, '/');
		if (c) {
			c = strchr(c + 1, '/');
			if (c)
				*c = 0;
		}
	}

	rl = journal_rate_limit_test(s->rate_limit, path,
		priority & LOG_PRIMASK, available_space(s, false));

	if (rl == 0)
		return;

	/* Write a suppression message if we suppressed something */
	if (rl > 1)
		server_driver_message(s, SD_MESSAGE_JOURNAL_DROPPED,
			"Suppressed %u messages from %s", rl - 1, path);

finish:
	dispatch_message_real(s, iovec, n, m, ucred, tv, label, label_len,
		unit_id, priority, object_pid);
}

int
server_flush_to_var(Server *s, bool require_flag_file)
{
	sd_id128_t machine;
	sd_journal *j = NULL;
	char ts[FORMAT_TIMESPAN_MAX];
	usec_t start;
	unsigned n = 0;
	int r;

	assert(s);

	if (!IN_SET(s->storage, STORAGE_AUTO, STORAGE_PERSISTENT))
		return 0;

	if (!s->runtime_journal)
		return 0;

	if (require_flag_file && !flushed_flag_is_set())
		return 0;

	system_journal_open(s, true, true);

	if (!s->system_journal)
		return 0;

	log_debug("Flushing to /var...");

	start = now(CLOCK_MONOTONIC);

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return r;

	r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY);
	if (r < 0)
		return log_error_errno(r, "Failed to read runtime journal: %m");

	sd_journal_set_data_threshold(j, 0);

	SD_JOURNAL_FOREACH(j)
	{
		Object *o = NULL;
		JournalFile *f;

		f = j->current_file;
		assert(f && f->current_offset > 0);

		n++;

		r = journal_file_move_to_object(f, OBJECT_ENTRY,
			f->current_offset, &o);
		if (r < 0) {
			log_error_errno(r, "Can't read entry: %m");
			goto finish;
		}

		r = journal_file_copy_entry(f, s->system_journal, o,
			f->current_offset, NULL, NULL, NULL);
		if (r >= 0)
			continue;

		if (!shall_try_append_again(s->system_journal, r)) {
			log_error_errno(r, "Can't write entry: %m");
			goto finish;
		}

		server_rotate(s);
		server_vacuum(s);

		if (!s->system_journal) {
			log_notice(
				"Didn't flush runtime journal since rotation of system journal wasn't successful.");
			r = -EIO;
			goto finish;
		}

		log_debug("Retrying write.");
		r = journal_file_copy_entry(f, s->system_journal, o,
			f->current_offset, NULL, NULL, NULL);
		if (r < 0) {
			log_error_errno(r, "Can't write entry: %m");
			goto finish;
		}
	}

finish:
	if (s->system_journal)
		journal_file_post_change(s->system_journal);

	journal_file_close(s->runtime_journal);
	s->runtime_journal = NULL;

	if (r >= 0)
		rm_rf(SVC_RUNTIMELOGDIR, false, true, false);

	sd_journal_close(j);

	server_driver_message(s, SD_ID128_NULL,
		"Time spent on flushing to /var is %s for %u entries.",
		format_timespan(ts, sizeof(ts), now(CLOCK_MONOTONIC) - start,
			0),
		n);

	return r;
}

int
server_process_datagram(sd_event_source *es, int fd, uint32_t revents,
	void *userdata)
{
	Server *s = userdata;
	struct socket_ucred ucred = { 0 }, *pucred = NULL;
	struct timeval *tv = NULL;
	struct cmsghdr *cmsg;
	char *label = NULL;
	size_t label_len = 0, m;
	struct iovec iovec;
	ssize_t n;
	int *fds = NULL, v = 0;
	unsigned n_fds = 0;

	union {
		struct cmsghdr cmsghdr;

		/* We use NAME_MAX space for the SELinux label
                 * here. The kernel currently enforces no
                 * limit, but according to suggestions from
                 * the SELinux people this will change and it
                 * will probably be identical to NAME_MAX. For
                 * now we use that, but this should be updated
                 * one day when the final limit is known. */
		uint8_t buf[
#ifdef CMSG_CREDS_STRUCT_SIZE
			CMSG_SPACE(CMSG_CREDS_STRUCT_SIZE) +
#endif
			CMSG_SPACE(sizeof(struct timeval)) +
			CMSG_SPACE(sizeof(int)) + /* fd */
			CMSG_SPACE(NAME_MAX)]; /* selinux label */
	} control = {};

	union sockaddr_union sa = {};

	struct msghdr msghdr = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = &control,
		.msg_controllen = sizeof(control),
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
	};

	assert(s);
	assert(fd == s->native_fd || fd == s->syslog_fd || fd == s->audit_fd);

	if (revents != EPOLLIN) {
		log_error(
			"Got invalid event from epoll for datagram fd: %" PRIx32,
			revents);
		return -EIO;
	}

#ifdef SIOCINQ
	/* Try to get the right size, if we can. (Not all
         * sockets support SIOCINQ, hence we just try, but
         * don't rely on it. */
	(void)ioctl(fd, SIOCINQ, &v);
#endif

#ifdef SVC_PLATFORM_Linux
	/* Fix it up, if it is too small. We use the same fixed value as auditd here. Awful! */
	m = PAGE_ALIGN(
		MAX3((size_t)v + 1, (size_t)LINE_MAX,
			ALIGN(sizeof(struct nlmsghdr)) +
				ALIGN((size_t)MAX_AUDIT_MESSAGE_LENGTH)) +
		1);
#else
	m = PAGE_ALIGN(MAX((size_t)v + 1, (size_t)LINE_MAX));
#endif

	if (!GREEDY_REALLOC(s->buffer, m))
		return log_oom();

	// HACK: UPSTREAM REMOVED THIS FROM GREEDY_ALLOC
	s->buffer_size = m;

	iovec.iov_base = s->buffer;
	iovec.iov_len = s->buffer_size -
		1; /* Leave room for trailing NUL we add later */

	n = recvmsg(fd, &msghdr, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		return log_error_errno(errno, "recvmsg() failed: %m");
	}

	CMSG_FOREACH (cmsg, &msghdr) {
		if (cmsg_readucred(cmsg, &ucred))
			pucred = &ucred;
#ifdef SCM_SECURITY
		else if (cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SCM_SECURITY) {
			label = (char *)CMSG_DATA(cmsg);
			label_len = cmsg->cmsg_len - CMSG_LEN(0);
		}
#endif
		else if (cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SO_TIMESTAMP &&
			cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
			tv = (struct timeval *)CMSG_DATA(cmsg);
		else if (cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SCM_RIGHTS) {
			fds = (int *)CMSG_DATA(cmsg);
			n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		}
	}

	/* And a trailing NUL, just in case */
	s->buffer[n] = 0;

	if (fd == s->syslog_fd) {
		if (n > 0 && n_fds == 0)
			server_process_syslog_message(s, s->buffer, n, pucred,
				tv, label, label_len);
		else if (n_fds > 0)
			log_warning(
				"Got file descriptors via syslog socket. Ignoring.");

	} else if (fd == s->native_fd) {
		if (n > 0 && n_fds == 0)
			server_process_native_message(s, s->buffer, n, pucred,
				tv, label, label_len);
		else if (n == 0 && n_fds == 1)
			server_process_native_file(s, fds[0], pucred, tv, label,
				label_len);
		else if (n_fds > 0)
			log_warning(
				"Got too many file descriptors via native socket. Ignoring.");

	} else {
#ifdef HAVE_AUDIT
		assert(fd == s->audit_fd);

		if (n > 0 && n_fds == 0)
			server_process_audit_message(s, s->buffer, n, pucred,
				&sa, msghdr.msg_namelen);
		else if (n_fds > 0)
			log_warning(
				"Got file descriptors via audit socket. Ignoring.");
#else
		log_error("Data received on unknown socket.");
#endif
	}

	close_many(fds, n_fds);
	return 0;
}

static int
dispatch_sigusr1(sd_event_source *es, const struct sigfd_siginfo *si,
	void *userdata)
{
	Server *s = userdata;

	assert(s);

	log_info("Received request to flush runtime journal from PID %" PRIu32,
		si->ssi_pid);

	(void)server_flush_to_var(s, false);
	server_sync(s);
	server_vacuum(s);

	touch(SVC_PKGRUNSTATEDIR "/journal/flushed");

	return 0;
}

static int
dispatch_sigusr2(sd_event_source *es, const struct sigfd_siginfo *si,
	void *userdata)
{
	Server *s = userdata;

	assert(s);

	log_info("Received request to rotate journal from PID %" PRIu32,
		si->ssi_pid);
	server_rotate(s);
	server_vacuum(s);

	return 0;
}

static int
dispatch_sigterm(sd_event_source *es, const struct sigfd_siginfo *si,
	void *userdata)
{
	Server *s = userdata;

	assert(s);

	log_received_signal(LOG_INFO, si);

	sd_event_exit(s->event, 0);
	return 0;
}

static int
setup_signals(Server *s)
{
	sigset_t mask;
	int r;

	assert(s);

	assert_se(sigemptyset(&mask) == 0);
	sigset_add_many(&mask, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, -1);
	assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

	r = sd_event_add_signal(s->event, &s->sigusr1_event_source, SIGUSR1,
		dispatch_sigusr1, s);
	if (r < 0)
		return r;

	r = sd_event_add_signal(s->event, &s->sigusr2_event_source, SIGUSR2,
		dispatch_sigusr2, s);
	if (r < 0)
		return r;

	r = sd_event_add_signal(s->event, &s->sigterm_event_source, SIGTERM,
		dispatch_sigterm, s);
	if (r < 0)
		return r;

	/* Let's process SIGTERM late, so that we flush all queued
         * messages to disk before we exit */
	r = sd_event_source_set_priority(s->sigterm_event_source,
		SD_EVENT_PRIORITY_NORMAL + 20);
	if (r < 0)
		return r;

	/* When journald is invoked on the terminal (when debugging),
         * it's useful if C-c is handled equivalent to SIGTERM. */
	r = sd_event_add_signal(s->event, &s->sigint_event_source, SIGINT,
		dispatch_sigterm, s);
	if (r < 0)
		return r;

	r = sd_event_source_set_priority(s->sigint_event_source,
		SD_EVENT_PRIORITY_NORMAL + 20);
	if (r < 0)
		return r;

	return 0;
}

static int
server_parse_proc_cmdline(Server *s)
{
	_cleanup_free_ char *line = NULL;
	const char *w, *state;
	size_t l;
	int r;

	r = proc_cmdline(&line);
	if (r < 0) {
		log_warning_errno(r,
			"Failed to read /proc/cmdline, ignoring: %m");
		return 0;
	}

	FOREACH_WORD_QUOTED(w, l, line, state)
	{
		_cleanup_free_ char *word;

		word = strndup(w, l);
		if (!word)
			return -ENOMEM;

		if (startswith(word, "systemd.journald.forward_to_syslog=")) {
			r = parse_boolean(word + 35);
			if (r < 0)
				log_warning(
					"Failed to parse forward to syslog switch %s. Ignoring.",
					word + 35);
			else
				s->forward_to_syslog = r;
		} else if (startswith(word,
				   "systemd.journald.forward_to_kmsg=")) {
			r = parse_boolean(word + 33);
			if (r < 0)
				log_warning(
					"Failed to parse forward to kmsg switch %s. Ignoring.",
					word + 33);
			else
				s->forward_to_kmsg = r;
		} else if (startswith(word,
				   "systemd.journald.forward_to_console=")) {
			r = parse_boolean(word + 36);
			if (r < 0)
				log_warning(
					"Failed to parse forward to console switch %s. Ignoring.",
					word + 36);
			else
				s->forward_to_console = r;
		} else if (startswith(word,
				   "systemd.journald.forward_to_wall=")) {
			r = parse_boolean(word + 33);
			if (r < 0)
				log_warning(
					"Failed to parse forward to wall switch %s. Ignoring.",
					word + 33);
			else
				s->forward_to_wall = r;
		} else if (startswith(word, "systemd.journald"))
			log_warning(
				"Invalid systemd.journald parameter. Ignoring.");
	}
	/* do not warn about state here, since probably systemd already did */

	return 0;
}

static int
server_parse_config_file(Server *s)
{
	assert(s);

	return config_parse_many(SVC_PKGSYSCONFDIR "/journald.conf",
		CONF_DIRS_NULSTR(SVC_PKGDIRNAME "/journald.conf"), "Journal\0",
		config_item_perf_lookup, journald_gperf_lookup, false, s);
}

static int
server_dispatch_sync(sd_event_source *es, usec_t t, void *userdata)
{
	Server *s = userdata;

	assert(s);

	server_sync(s);
	return 0;
}

int
server_schedule_sync(Server *s, int priority)
{
	int r;

	assert(s);

	if (priority <= LOG_CRIT) {
		/* Immediately sync to disk when this is of priority CRIT, ALERT, EMERG */
		server_sync(s);
		return 0;
	}

	if (s->sync_scheduled)
		return 0;

	if (s->sync_interval_usec > 0) {
		usec_t when;

		r = sd_event_now(s->event, CLOCK_MONOTONIC, &when);
		if (r < 0)
			return r;

		when += s->sync_interval_usec;

		if (!s->sync_event_source) {
			r = sd_event_add_time(s->event, &s->sync_event_source,
				CLOCK_MONOTONIC, when, 0, server_dispatch_sync,
				s);
			if (r < 0)
				return r;

			r = sd_event_source_set_priority(s->sync_event_source,
				SD_EVENT_PRIORITY_IMPORTANT);
		} else {
			r = sd_event_source_set_time(s->sync_event_source,
				when);
			if (r < 0)
				return r;

			r = sd_event_source_set_enabled(s->sync_event_source,
				SD_EVENT_ONESHOT);
		}
		if (r < 0)
			return r;

		s->sync_scheduled = true;
	}

	return 0;
}

static int
dispatch_hostname_change(sd_event_source *es, int fd, uint32_t revents,
	void *userdata)
{
	Server *s = userdata;

	assert(s);

	server_cache_hostname(s);
	return 0;
}

static int
server_open_hostname(Server *s)
{
#ifdef SVC_PLATFORM_Linux
	int r;

	assert(s);

	s->hostname_fd = open("/proc/sys/kernel/hostname",
		O_RDONLY | O_CLOEXEC | O_NDELAY | O_NOCTTY);
	if (s->hostname_fd < 0)
		return log_error_errno(errno,
			"Failed to open /proc/sys/kernel/hostname: %m");

	r = sd_event_add_io(s->event, &s->hostname_event_source, s->hostname_fd,
		0, dispatch_hostname_change, s);
	if (r < 0) {
		/* kernels prior to 3.2 don't support polling this file. Ignore
                 * the failure. */
		if (r == -EPERM) {
			log_warning(
				"Failed to register hostname fd in event loop: %s. Ignoring.",
				strerror(-r));
			s->hostname_fd = safe_close(s->hostname_fd);
			return 0;
		}

		return log_error_errno(r,
			"Failed to register hostname fd in event loop: %m");
	}

	r = sd_event_source_set_priority(s->hostname_event_source,
		SD_EVENT_PRIORITY_IMPORTANT - 10);
	if (r < 0)
		return log_error_errno(r,
			"Failed to adjust priority of host name event source: %m");
#endif

	return 0;
}

static int
dispatch_notify_event(sd_event_source *es, int fd, uint32_t revents,
	void *userdata)
{
	Server *s = userdata;
	int r;

	assert(s);
	assert(s->notify_event_source == es);
	assert(s->notify_fd == fd);

	if (revents != EPOLLOUT) {
		log_error("Invalid events on notify file descriptor.");
		return -EINVAL;
	}

	/* The $NOTIFY_SOCKET is writable again, now send exactly one
         * message on it. Either it's the wtachdog event, the initial
         * READY=1 event or an stdout stream event. If there's nothing
         * to write anymore, turn our event source off. The next time
         * there's something to send it will be turned on again. */

	if (!s->sent_notify_ready) {
		static const char p[] = "READY=1\n"
					"STATUS=Processing requests...";
		ssize_t l;

		l = send(s->notify_fd, p, strlen(p), MSG_DONTWAIT);
		if (l < 0) {
			if (errno == EAGAIN)
				return 0;

			return log_error_errno(errno,
				"Failed to send READY=1 notification message: %m");
		}

		s->sent_notify_ready = true;
		log_debug("Sent READY=1 notification.");

	} else if (s->send_watchdog) {
		static const char p[] = "WATCHDOG=1";

		ssize_t l;

		l = send(s->notify_fd, p, strlen(p), MSG_DONTWAIT);
		if (l < 0) {
			if (errno == EAGAIN)
				return 0;

			return log_error_errno(errno,
				"Failed to send WATCHDOG=1 notification message: %m");
		}

		s->send_watchdog = false;
		log_debug("Sent WATCHDOG=1 notification.");

	} else if (s->stdout_streams_notify_queue)
		/* Dispatch one stream notification event */
		stdout_stream_send_notify(s->stdout_streams_notify_queue);

	/* Leave us enabled if there's still more to to do. */
	if (s->send_watchdog || s->stdout_streams_notify_queue)
		return 0;

	/* There was nothing to do anymore, let's turn ourselves off. */
	r = sd_event_source_set_enabled(es, SD_EVENT_OFF);
	if (r < 0)
		return log_error_errno(r,
			"Failed to turn off notify event source: %m");

	return 0;
}

static int
dispatch_watchdog(sd_event_source *es, uint64_t usec, void *userdata)
{
	Server *s = userdata;
	int r;

	assert(s);

	s->send_watchdog = true;

	r = sd_event_source_set_enabled(s->notify_event_source, SD_EVENT_ON);
	if (r < 0)
		log_warning_errno(r,
			"Failed to turn on notify event source: %m");

	r = sd_event_source_set_time(s->watchdog_event_source,
		usec + s->watchdog_usec / 2);
	if (r < 0)
		return log_error_errno(r,
			"Failed to restart watchdog event source: %m");

	r = sd_event_source_set_enabled(s->watchdog_event_source, SD_EVENT_ON);
	if (r < 0)
		return log_error_errno(r,
			"Failed to enable watchdog event source: %m");

	return 0;
}

static int
server_connect_notify(Server *s)
{
	union sockaddr_union sa = {
		.un.sun_family = AF_UNIX,
	};
	const char *e;
	int r;

	assert(s);
	assert(s->notify_fd < 0);
	assert(!s->notify_event_source);

	/*
          So here's the problem: we'd like to send notification
          messages to PID 1, but we cannot do that via sd_notify(),
          since that's synchronous, and we might end up blocking on
          it. Specifically: given that PID 1 might block on
          dbus-daemon during IPC, and dbus-daemon is logging to us,
          and might hence block on us, we might end up in a deadlock
          if we block on sending PID 1 notification messages -- by
          generating a full blocking circle. To avoid this, let's
          create a non-blocking socket, and connect it to the
          notification socket, and then wait for POLLOUT before we
          send anything. This should efficiently avoid any deadlocks,
          as we'll never block on PID 1, hence PID 1 can safely block
          on dbus-daemon which can safely block on us again.

          Don't think that this issue is real? It is, see:
          https://github.com/systemd/systemd/issues/1505
        */

	e = getenv("NOTIFY_SOCKET");
	if (!e)
		return 0;

	if ((e[0] != '@' && e[0] != '/') || e[1] == 0) {
		log_error("NOTIFY_SOCKET set to an invalid value: %s", e);
		return -EINVAL;
	}

	if (strlen(e) > sizeof(sa.un.sun_path)) {
		log_error("NOTIFY_SOCKET path too long: %s", e);
		return -EINVAL;
	}

	s->notify_fd = socket(AF_UNIX,
		SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s->notify_fd < 0)
		return log_error_errno(errno,
			"Failed to create notify socket: %m");

	(void)fd_inc_sndbuf(s->notify_fd, NOTIFY_SNDBUF_SIZE);

	strncpy(sa.un.sun_path, e, sizeof(sa.un.sun_path));
	if (sa.un.sun_path[0] == '@')
		sa.un.sun_path[0] = 0;

	r = connect(s->notify_fd, &sa.sa,
		offsetof(struct sockaddr_un, sun_path) + strlen(e));
	if (r < 0)
		return log_error_errno(errno,
			"Failed to connect to notify socket: %m");

	r = sd_event_add_io(s->event, &s->notify_event_source, s->notify_fd,
		EPOLLOUT, dispatch_notify_event, s);
	if (r < 0)
		return log_error_errno(r,
			"Failed to watch notification socket: %m");

	if (sd_watchdog_enabled(false, &s->watchdog_usec) > 0) {
		s->send_watchdog = true;

		r = sd_event_add_time(s->event, &s->watchdog_event_source,
			CLOCK_MONOTONIC,
			now(CLOCK_MONOTONIC) + s->watchdog_usec / 2,
			s->watchdog_usec / 4, dispatch_watchdog, s);
		if (r < 0)
			return log_error_errno(r,
				"Failed to add watchdog time event: %m");
	}

	/* This should fire pretty soon, which we'll use to send the
         * READY=1 event. */

	return 0;
}

int
server_init(Server *s)
{
	_cleanup_fdset_free_ FDSet *fds = NULL;
	int n, r, fd;

	assert(s);

	zero(*s);
	s->syslog_fd = s->native_fd = s->stdout_fd = s->dev_kmsg_fd =
		s->audit_fd = s->hostname_fd = s->notify_fd = -1;
	s->compress = true;
	s->seal = true;

	s->watchdog_usec = USEC_INFINITY;

	s->sync_interval_usec = DEFAULT_SYNC_INTERVAL_USEC;
	s->sync_scheduled = false;

	s->rate_limit_interval = DEFAULT_RATE_LIMIT_INTERVAL;
	s->rate_limit_burst = DEFAULT_RATE_LIMIT_BURST;

	s->forward_to_syslog = true;
	s->forward_to_wall = true;

	s->max_file_usec = DEFAULT_MAX_FILE_USEC;

	s->max_level_store = LOG_DEBUG;
	s->max_level_syslog = LOG_DEBUG;
	s->max_level_kmsg = LOG_NOTICE;
	s->max_level_console = LOG_INFO;
	s->max_level_wall = LOG_EMERG;

	s->line_max = DEFAULT_LINE_MAX;

	memset(&s->system_metrics, 0xFF, sizeof(s->system_metrics));
	memset(&s->runtime_metrics, 0xFF, sizeof(s->runtime_metrics));

	server_parse_config_file(s);
	server_parse_proc_cmdline(s);
	if (!!s->rate_limit_interval ^ !!s->rate_limit_burst) {
		log_debug(
			"Setting both rate limit interval and burst from " USEC_FMT
			",%u to 0,0",
			s->rate_limit_interval, s->rate_limit_burst);
		s->rate_limit_interval = s->rate_limit_burst = 0;
	}

	mkdir_p(SVC_PKGRUNSTATEDIR "/journal", 0755);

	s->user_journals = ordered_hashmap_new(NULL);
	if (!s->user_journals)
		return log_oom();

	s->mmap = mmap_cache_new();
	if (!s->mmap)
		return log_oom();

	r = sd_event_default(&s->event);
	if (r < 0)
		return log_error_errno(r, "Failed to create event loop: %m");

	n = sd_listen_fds(true);
	if (n < 0)
		return log_error_errno(n,
			"Failed to read listening file descriptors from environment: %m");

	for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
		if (sd_is_socket_unix(fd, SOCK_DGRAM, -1,
			    SVC_PKGRUNSTATEDIR "/journal/socket", 0) > 0) {
			if (s->native_fd >= 0) {
				log_error("Too many native sockets passed.");
				return -EINVAL;
			}

			s->native_fd = fd;

		} else if (sd_is_socket_unix(fd, SOCK_STREAM, 1,
				   SVC_PKGRUNSTATEDIR "/journal/stdout",
				   0) > 0) {
			if (s->stdout_fd >= 0) {
				log_error("Too many stdout sockets passed.");
				return -EINVAL;
			}

			s->stdout_fd = fd;

		} else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, DEV_LOG, 0) >
			0) {
			if (s->syslog_fd >= 0) {
				log_error(
					"Too many BSD syslog sockets passed.");
				return -EINVAL;
			}

			s->syslog_fd = fd;

		}
#ifdef AF_NETLINK
		else if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {
			if (s->audit_fd >= 0) {
				log_error("Too many audit sockets passed.");
				return -EINVAL;
			}

			s->audit_fd = fd;

		}
#endif
		else {
			if (!fds) {
				fds = fdset_new();
				if (!fds)
					return log_oom();
			}

			r = fdset_put(fds, fd);
			if (r < 0)
				return log_oom();
		}
	}

	r = server_open_stdout_socket(s, fds);
	if (r < 0)
		return r;

	if (fdset_size(fds) > 0) {
		log_warning("%u unknown file descriptors passed, closing.",
			fdset_size(fds));
		fds = fdset_free(fds);
	}

	r = server_open_syslog_socket(s);
	if (r < 0)
		return r;

	r = server_open_native_socket(s);
	if (r < 0)
		return r;

	r = server_open_dev_kmsg(s);
	if (r < 0)
		return r;

	r = server_open_kernel_seqnum(s);
	if (r < 0)
		return r;

	r = server_open_hostname(s);
	if (r < 0)
		return r;

	r = setup_signals(s);
	if (r < 0)
		return r;

#ifdef SVC_USE_libudev
	s->udev = udev_new();
	if (!s->udev)
		return -ENOMEM;
#endif

	s->rate_limit = journal_rate_limit_new(s->rate_limit_interval,
		s->rate_limit_burst);
	if (!s->rate_limit)
		return -ENOMEM;

	r = cg_get_root_path(&s->cgroup_root);
	if (r < 0)
		return r;

	server_cache_hostname(s);
	server_cache_boot_id(s);
	server_cache_machine_id(s);

	(void)server_connect_notify(s);

	r = system_journal_open(s, false, true);
	if (r < 0)
		return r;

	return 0;
}

void
server_maybe_append_tags(Server *s)
{
#ifdef HAVE_GCRYPT
	JournalFile *f;
	Iterator i;
	usec_t n;

	n = now(CLOCK_REALTIME);

	if (s->system_journal)
		journal_file_maybe_append_tag(s->system_journal, n);

	ORDERED_HASHMAP_FOREACH (f, s->user_journals, i)
		journal_file_maybe_append_tag(f, n);
#endif
}

void
server_done(Server *s)
{
	JournalFile *f;
	assert(s);

	while (s->stdout_streams)
		stdout_stream_free(s->stdout_streams);

	(void)journal_file_close(s->system_journal);
	(void)journal_file_close(s->runtime_journal);

	while ((f = ordered_hashmap_steal_first(s->user_journals)))
		journal_file_close(f);

	ordered_hashmap_free(s->user_journals);

	sd_event_source_unref(s->syslog_event_source);
	sd_event_source_unref(s->native_event_source);
	sd_event_source_unref(s->stdout_event_source);
	sd_event_source_unref(s->dev_kmsg_event_source);
	sd_event_source_unref(s->audit_event_source);
	sd_event_source_unref(s->sync_event_source);
	sd_event_source_unref(s->sigusr1_event_source);
	sd_event_source_unref(s->sigusr2_event_source);
	sd_event_source_unref(s->sigterm_event_source);
	sd_event_source_unref(s->sigint_event_source);
	sd_event_source_unref(s->hostname_event_source);
	sd_event_source_unref(s->notify_event_source);
	sd_event_source_unref(s->watchdog_event_source);
	sd_event_unref(s->event);

	safe_close(s->syslog_fd);
	safe_close(s->native_fd);
	safe_close(s->stdout_fd);
	safe_close(s->dev_kmsg_fd);
	safe_close(s->audit_fd);
	safe_close(s->hostname_fd);
	safe_close(s->notify_fd);

	if (s->rate_limit)
		journal_rate_limit_free(s->rate_limit);

	if (s->kernel_seqnum)
		munmap(s->kernel_seqnum, sizeof(uint64_t));

	free(s->buffer);
	free(s->tty_path);
	free(s->cgroup_root);
	free(s->hostname_field);

	if (s->mmap)
		mmap_cache_unref(s->mmap);

#ifdef SVC_USE_libudev
	if (s->udev)
		udev_unref(s->udev);
#endif
}
