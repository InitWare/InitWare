/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <sys/signal.h>

//#include <libudev.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-messages.h>

#include "cgroup-util.h"
#include "conf-parser.h"
#include "fileio.h"

#include "ev-util.h"
#include "hashmap.h"
#include "journal-authenticate.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-native.h"
#include "journald-rate-limit.h"
#include "journald-server.h"
#include "journald-stream.h"
#include "journald-syslog.h"
#include "list.h"
#include "missing.h"
#include "mkdir.h"
#include "socket-util.h"
#include "virt.h"

#ifdef Sys_Plat_Linux
#include <linux/sockios.h>
#endif

#ifdef Have_sys_statvfs_h
#include <sys/statvfs.h>
#endif

#ifdef HAVE_ACL
#include <sys/acl.h>
#include <acl/libacl.h>
#include "acl-util.h"
#endif

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#define USER_JOURNALS_MAX 1024

#define DEFAULT_SYNC_INTERVAL_USEC (5 * USEC_PER_MINUTE)
#define DEFAULT_RATE_LIMIT_INTERVAL (30 * USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 1000
#define DEFAULT_MAX_FILE_USEC USEC_PER_MONTH

#define RECHECK_AVAILABLE_SPACE_USEC (30 * USEC_PER_SEC)

static const char *const storage_table[] = {
	[STORAGE_AUTO] = "auto", [STORAGE_VOLATILE] = "volatile", [STORAGE_PERSISTENT] = "persistent", [STORAGE_NONE] = "none"
};

DEFINE_STRING_TABLE_LOOKUP(storage, Storage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_storage, storage, Storage, "Failed to parse storage setting");

static const char *const split_mode_table[] = {
	[SPLIT_NONE] = "none", [SPLIT_UID] = "uid", [SPLIT_LOGIN] = "login"
};

DEFINE_STRING_TABLE_LOOKUP(split_mode, SplitMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_split_mode, split_mode, SplitMode,
    "Failed to parse split mode setting");

static uint64_t available_space(Server *s, bool verbose)
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

	if (s->cached_available_space_timestamp + RECHECK_AVAILABLE_SPACE_USEC > ts && !verbose)
		return s->cached_available_space;

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return 0;

	if (s->system_journal) {
		f = "/var/log/evlog/";
		m = &s->system_metrics;
	} else {
		f = INSTALL_PKGRUNSTATE_DIR "/evlog/";
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
		union dirent_storage buf;

		r = readdir_r(d, &buf.de, &de);
		if (r != 0)
			break;

		if (!de)
			break;

		if (!endswith(de->d_name, ".journal") && !endswith(de->d_name, ".journal~"))
			continue;

		if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
			continue;

		if (!S_ISREG(st.st_mode))
			continue;

		sum += (uint64_t) st.st_blocks * 512UL;
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
		char fb1[FORMAT_BYTES_MAX], fb2[FORMAT_BYTES_MAX], fb3[FORMAT_BYTES_MAX],
		    fb4[FORMAT_BYTES_MAX], fb5[FORMAT_BYTES_MAX];

		server_driver_message(s, SD_MESSAGE_JOURNAL_USAGE,
		    "%s journal is using %s (max allowed %s, "
		    "trying to leave %s free of %s available ??? current limit %s).",
		    s->system_journal ? "Permanent" : "Runtime",
		    format_bytes(fb1, sizeof(fb1), sum), format_bytes(fb2, sizeof(fb2), m->max_use),
		    format_bytes(fb3, sizeof(fb3), m->keep_free),
		    format_bytes(fb4, sizeof(fb4), ss_avail),
		    format_bytes(fb5, sizeof(fb5), s->cached_available_space + sum));
	}

	return s->cached_available_space;
}

void server_fix_perms(Server *s, JournalFile *f, uid_t uid)
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
		log_warning("Failed to fix access mode on %s, ignoring: %s", f->path, strerror(-r));

#ifdef HAVE_ACL
	if (uid <= 0)
		return;

	acl = acl_get_fd(f->fd);
	if (!acl) {
		log_warning("Failed to read ACL on %s, ignoring: %m", f->path);
		return;
	}

	r = acl_find_uid(acl, uid, &entry);
	if (r <= 0) {

		if (acl_create_entry(&acl, &entry) < 0 || acl_set_tag_type(entry, ACL_USER) < 0 ||
		    acl_set_qualifier(entry, &uid) < 0) {
			log_warning("Failed to patch ACL on %s, ignoring: %m", f->path);
			goto finish;
		}
	}

	/* We do not recalculate the mask unconditionally here,
	 * so that the fchmod() mask above stays intact. */
	if (acl_get_permset(entry, &permset) < 0 || acl_add_perm(permset, ACL_READ) < 0 ||
	    calc_acl_mask_if_needed(&acl) < 0) {
		log_warning("Failed to patch ACL on %s, ignoring: %m", f->path);
		goto finish;
	}

	if (acl_set_fd(f->fd, acl) < 0)
		log_warning("Failed to set ACL on %s, ignoring: %m", f->path);

finish:
	acl_free(acl);
#endif
}

static JournalFile *find_journal(Server *s, uid_t uid)
{
	_cleanup_free_ char *p = NULL;
	int r;
	JournalFile *f;
	sd_id128_t machine;

	assert(s);

	/* We split up user logs only on /var, not on /run. If the
	 * runtime file is open, we write to it exclusively, in order
	 * to guarantee proper order as soon as we flush /run to
	 * /var and close the runtime file. */

	if (s->runtime_journal)
		return s->runtime_journal;

	if (uid <= 0)
		return s->system_journal;

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return s->system_journal;

	f = hashmap_get(s->user_journals, UINT32_TO_PTR(uid));
	if (f)
		return f;

	if (asprintf(&p, "/var/log/evlog/" SD_ID128_FORMAT_STR "/user-%lu.journal",
		SD_ID128_FORMAT_VAL(machine), (unsigned long) uid) < 0)
		return s->system_journal;

	while (hashmap_size(s->user_journals) >= USER_JOURNALS_MAX) {
		/* Too many open? Then let's close one */
		f = hashmap_steal_first(s->user_journals);
		assert(f);
		journal_file_close(f);
	}

	r = journal_file_open_reliably(p, O_RDWR | O_CREAT, 0640, s->compress, s->seal,
	    &s->system_metrics, s->mmap, NULL, &f);
	if (r < 0)
		return s->system_journal;

	server_fix_perms(s, f, uid);

	r = hashmap_put(s->user_journals, UINT32_TO_PTR(uid), f);
	if (r < 0) {
		journal_file_close(f);
		return s->system_journal;
	}

	return f;
}

void server_rotate(Server *s)
{
	JournalFile *f;
	void *k;
	Iterator i;
	int r;

	log_debug("Rotating...");

	if (s->runtime_journal) {
		r = journal_file_rotate(&s->runtime_journal, s->compress, false);
		if (r < 0)
			if (s->runtime_journal)
				log_error("Failed to rotate %s: %s", s->runtime_journal->path,
				    strerror(-r));
			else
				log_error("Failed to create new runtime journal: %s", strerror(-r));
		else
			server_fix_perms(s, s->runtime_journal, 0);
	}

	if (s->system_journal) {
		r = journal_file_rotate(&s->system_journal, s->compress, s->seal);
		if (r < 0)
			if (s->system_journal)
				log_error("Failed to rotate %s: %s", s->system_journal->path,
				    strerror(-r));
			else
				log_error("Failed to create new system journal: %s", strerror(-r));

		else
			server_fix_perms(s, s->system_journal, 0);
	}

	HASHMAP_FOREACH_KEY (f, k, s->user_journals, i) {
		r = journal_file_rotate(&f, s->compress, s->seal);
		if (r < 0)
			if (f)
				log_error("Failed to rotate %s: %s", f->path, strerror(-r));
			else {
				log_error("Failed to create user journal: %s", strerror(-r));
				hashmap_remove(s->user_journals, k);
			}
		else {
			hashmap_replace(s->user_journals, k, f);
			server_fix_perms(s, f, PTR_TO_UINT32(k));
		}
	}
}

void server_sync(Server *s)
{
	JournalFile *f;
	void *k;
	Iterator i;
	int r;

	if (s->system_journal) {
		r = journal_file_set_offline(s->system_journal);
		if (r < 0)
			log_error("Failed to sync system journal: %s", strerror(-r));
	}

	HASHMAP_FOREACH_KEY (f, k, s->user_journals, i) {
		r = journal_file_set_offline(f);
		if (r < 0)
			log_error("Failed to sync user journal: %s", strerror(-r));
	}

	ev_timer_stop(s->evloop, &s->sync_timer_watch);

	s->sync_scheduled = false;
}

void server_vacuum(Server *s)
{
	char ids[33];
	sd_id128_t machine;
	int r;

	log_debug("Vacuuming...");

	s->oldest_file_usec = 0;

	r = sd_id128_get_machine(&machine);
	if (r < 0) {
		log_error("Failed to get machine ID: %s", strerror(-r));
		return;
	}

	sd_id128_to_string(machine, ids);

	if (s->system_journal) {
		char *p = strappenda("/var/log/evlog/", ids);

		r = journal_directory_vacuum(p, s->system_metrics.max_use, s->max_retention_usec,
		    &s->oldest_file_usec);
		if (r < 0 && r != -ENOENT)
			log_error("Failed to vacuum %s: %s", p, strerror(-r));
	}

	if (s->runtime_journal) {
		char *p = strappenda((INSTALL_PKGRUNSTATE_DIR "/evlog"), ids);

		r = journal_directory_vacuum(p, s->runtime_metrics.max_use, s->max_retention_usec,
		    &s->oldest_file_usec);
		if (r < 0 && r != -ENOENT)
			log_error("Failed to vacuum %s: %s", p, strerror(-r));
	}

	s->cached_available_space_timestamp = 0;
}

bool shall_try_append_again(JournalFile *f, int r)
{

	/* -E2BIG            Hit configured limit
	   -EFBIG            Hit fs limit
	   -EDQUOT           Quota limit hit
	   -ENOSPC           Disk full
	   -EHOSTDOWN        Other machine
	   -EBUSY            Unclean shutdown
	   -EPROTONOSUPPORT  Unsupported feature
	   -EBADMSG          Corrupted
	   -ENODATA          Truncated
	   -ESHUTDOWN        Already archived */

	if (r == -E2BIG || r == -EFBIG || r == -EDQUOT || r == -ENOSPC)
		log_debug("%s: Allocation limit reached, rotating.", f->path);
	else if (r == -EHOSTDOWN)
		log_info("%s: Journal file from other machine, rotating.", f->path);
	else if (r == -EBUSY)
		log_info("%s: Unclean shutdown, rotating.", f->path);
	else if (r == -EPROTONOSUPPORT)
		log_info("%s: Unsupported feature, rotating.", f->path);
	else if (r == -EBADMSG || r == -ENODATA || r == ESHUTDOWN)
		log_warning("%s: Journal file corrupted, rotating.", f->path);
	else
		return false;

	return true;
}

static void write_to_journal(Server *s, uid_t uid, struct iovec *iovec, unsigned n, int priority)
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
		log_debug("%s: Journal header limits reached or header out-of-date, rotating.",
		    f->path);
		server_rotate(s);
		server_vacuum(s);
		vacuumed = true;

		f = find_journal(s, uid);
		if (!f)
			return;
	}

	r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);
	if (r >= 0) {
		server_schedule_sync(s, priority);
		return;
	}

	if (vacuumed || !shall_try_append_again(f, r)) {
		size_t size = 0;
		unsigned i;
		for (i = 0; i < n; i++)
			size += iovec[i].iov_len;

		log_error("Failed to write entry (%d items, %zu bytes), ignoring: %s", n, size,
		    strerror(-r));
		return;
	}

	server_rotate(s);
	server_vacuum(s);

	f = find_journal(s, uid);
	if (!f)
		return;

	log_debug("Retrying write.");
	r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);
	if (r < 0) {
		size_t size = 0;
		unsigned i;
		for (i = 0; i < n; i++)
			size += iovec[i].iov_len;

		log_error("Failed to write entry (%d items, %zu bytes) despite vacuuming, ignoring: %s",
		    n, size, strerror(-r));
	} else
		server_schedule_sync(s, priority);
}

static void dispatch_message_real(Server *s, struct iovec *iovec, unsigned n, unsigned m,
    struct socket_ucred *ucred, struct timeval *tv, const char *label, size_t label_len,
    const char *unit_id, int priority, pid_t object_pid)
{

	char pid[sizeof("_PID=") + DECIMAL_STR_MAX(unsigned long)],
	    uid[sizeof("_UID=") + DECIMAL_STR_MAX(unsigned long)],
	    gid[sizeof("_GID=") + DECIMAL_STR_MAX(unsigned long)],
	    owner_uid[sizeof("_SYSTEMD_OWNER_UID=") + DECIMAL_STR_MAX(uid_t)],
	    source_time[sizeof("_SOURCE_REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t)],
	    boot_id[sizeof("_BOOT_ID=") + 32] = "_BOOT_ID=",
					  machine_id[sizeof("_MACHINE_ID=") + 32] = "_MACHINE_ID=",
					  o_uid[sizeof("OBJECT_UID=") + DECIMAL_STR_MAX(uid_t)],
					  o_gid[sizeof("OBJECT_GID=") + DECIMAL_STR_MAX(gid_t)],
					  o_owner_uid[sizeof("OBJECT_SYSTEMD_OWNER_UID=") +
					      DECIMAL_STR_MAX(uid_t)];
	uid_t object_uid;
	gid_t object_gid;
	char *x;
	sd_id128_t id;
	int r;
	char *t, *c;
	uid_t realuid = 0, owner = 0, journal_uid;
	bool owner_valid = false;
#ifdef HAVE_AUDIT
	char audit_session[sizeof("_AUDIT_SESSION=") + DECIMAL_STR_MAX(uint32_t)],
	    audit_loginuid[sizeof("_AUDIT_LOGINUID=") + DECIMAL_STR_MAX(uid_t)],
	    o_audit_session[sizeof("OBJECT_AUDIT_SESSION=") + DECIMAL_STR_MAX(uint32_t)],
	    o_audit_loginuid[sizeof("OBJECT_AUDIT_LOGINUID=") + DECIMAL_STR_MAX(uid_t)];

	uint32_t audit;
	uid_t loginuid;
#endif

	assert(s);
	assert(iovec);
	assert(n > 0);
	assert(n + N_IOVEC_META_FIELDS + (object_pid ? N_IOVEC_OBJECT_FIELDS : 0) <= m);

	if (ucred) {
		realuid = ucred->uid;

		if (ucred->pid != -1) {
			sprintf(pid, "_PID=%lu", (unsigned long) ucred->pid);
			IOVEC_SET_STRING(iovec[n++], pid);
		}

		if (ucred->uid != -1) {
			sprintf(uid, "_UID=%lu", (unsigned long) ucred->uid);
			IOVEC_SET_STRING(iovec[n++], uid);
		}

		if (ucred->gid != -1) {
			sprintf(gid, "_GID=%lu", (unsigned long) ucred->gid);
			IOVEC_SET_STRING(iovec[n++], gid);
		}

		r = get_process_comm(ucred->pid, &t);
		if (r >= 0) {
			x = strappenda("_COMM=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_exe(ucred->pid, &t);
		if (r >= 0) {
			x = strappenda("_EXE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		/* FIXME: */
		r = get_process_cmdline(ucred->pid, 0, false, &t);
		if (r >= 0) {
			x = strappenda("_CMDLINE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

#ifdef Sys_Plat_Linux
		r = get_process_capeff(ucred->pid, &t);
		if (r >= 0) {
			x = strappenda("_CAP_EFFECTIVE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}
#endif

#ifdef HAVE_AUDIT
		r = audit_session_from_pid(ucred->pid, &audit);
		if (r >= 0) {
			sprintf(audit_session, "_AUDIT_SESSION=%lu", (unsigned long) audit);
			IOVEC_SET_STRING(iovec[n++], audit_session);
		}

		r = audit_loginuid_from_pid(ucred->pid, &loginuid);
		if (r >= 0) {
			sprintf(audit_loginuid, "_AUDIT_LOGINUID=%lu", (unsigned long) loginuid);
			IOVEC_SET_STRING(iovec[n++], audit_loginuid);
		}
#endif

#ifdef Use_CGroups
		r = cg_pid_get_path_shifted(ucred->pid, NULL, &c);
		if (r >= 0) {
			char *session = NULL;

			x = strappenda("_SYSTEMD_CGROUP=", c);
			IOVEC_SET_STRING(iovec[n++], x);

			r = cg_path_get_session(c, &t);
			if (r >= 0) {
				session = strappenda("_SYSTEMD_SESSION=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], session);
			}

			if (cg_path_get_owner_uid(c, &owner) >= 0) {
				owner_valid = true;

				sprintf(owner_uid, "_SYSTEMD_OWNER_UID=%lu", (unsigned long) owner);
				IOVEC_SET_STRING(iovec[n++], owner_uid);
			}

			if (cg_path_get_unit(c, &t) >= 0) {
				x = strappenda("_SYSTEMD_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			} else if (unit_id && !session) {
				x = strappenda("_SYSTEMD_UNIT=", unit_id);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_user_unit(c, &t) >= 0) {
				x = strappenda("_SYSTEMD_USER_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			} else if (unit_id && session) {
				x = strappenda("_SYSTEMD_USER_UNIT=", unit_id);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_slice(c, &t) >= 0) {
				x = strappenda("_SYSTEMD_SLICE=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			free(c);
		} else
#endif
		    if (unit_id) {
			x = strappenda("_SYSTEMD_UNIT=", unit_id);
			IOVEC_SET_STRING(iovec[n++], x);
		}

#ifdef HAVE_SELINUX
		if (label) {
			x = alloca(sizeof("_SELINUX_CONTEXT=") + label_len);

			*((char *) mempcpy(stpcpy(x, "_SELINUX_CONTEXT="), label, label_len)) = 0;
			IOVEC_SET_STRING(iovec[n++], x);
		} else {
			security_context_t con;

			if (getpidcon(ucred->pid, &con) >= 0) {
				x = strappenda("_SELINUX_CONTEXT=", con);

				freecon(con);
				IOVEC_SET_STRING(iovec[n++], x);
			}
		}
#endif
	}
	assert(n <= m);

	if (object_pid) {
		r = get_process_uid(object_pid, &object_uid);
		if (r >= 0) {
			sprintf(o_uid, "OBJECT_UID=%lu", (unsigned long) object_uid);
			IOVEC_SET_STRING(iovec[n++], o_uid);
		}

		r = get_process_gid(object_pid, &object_gid);
		if (r >= 0) {
			sprintf(o_gid, "OBJECT_GID=%lu", (unsigned long) object_gid);
			IOVEC_SET_STRING(iovec[n++], o_gid);
		}

		r = get_process_comm(object_pid, &t);
		if (r >= 0) {
			x = strappenda("OBJECT_COMM=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

#ifdef Sys_Plat_Linux
		r = get_process_exe(object_pid, &t);
		if (r >= 0) {
			x = strappenda("OBJECT_EXE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}

		r = get_process_cmdline(object_pid, 0, false, &t);
		if (r >= 0) {
			x = strappenda("OBJECT_CMDLINE=", t);
			free(t);
			IOVEC_SET_STRING(iovec[n++], x);
		}
#endif

#ifdef HAVE_AUDIT
		r = audit_session_from_pid(object_pid, &audit);
		if (r >= 0) {
			sprintf(o_audit_session, "OBJECT_AUDIT_SESSION=%lu", (unsigned long) audit);
			IOVEC_SET_STRING(iovec[n++], o_audit_session);
		}

		r = audit_loginuid_from_pid(object_pid, &loginuid);
		if (r >= 0) {
			sprintf(o_audit_loginuid, "OBJECT_AUDIT_LOGINUID=%lu",
			    (unsigned long) loginuid);
			IOVEC_SET_STRING(iovec[n++], o_audit_loginuid);
		}
#endif

		/*r = cg_pid_get_path_shifted(object_pid, NULL, &c);
		if (r >= 0) {
			x = strappenda("OBJECT_SYSTEMD_CGROUP=", c);
			IOVEC_SET_STRING(iovec[n++], x);

			r = cg_path_get_session(c, &t);
			if (r >= 0) {
				x = strappenda("OBJECT_SYSTEMD_SESSION=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_owner_uid(c, &owner) >= 0) {
				sprintf(o_owner_uid, "OBJECT_SYSTEMD_OWNER_UID=%lu", (unsigned
		long) owner); IOVEC_SET_STRING(iovec[n++], o_owner_uid);
			}

			if (cg_path_get_unit(c, &t) >= 0) {
				x = strappenda("OBJECT_SYSTEMD_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			if (cg_path_get_user_unit(c, &t) >= 0) {
				x = strappenda("OBJECT_SYSTEMD_USER_UNIT=", t);
				free(t);
				IOVEC_SET_STRING(iovec[n++], x);
			}

			free(c);
		}*/
	}
	assert(n <= m);

	if (tv) {
		sprintf(source_time, "_SOURCE_REALTIME_TIMESTAMP=%llu",
		    (unsigned long long) timeval_load(tv));
		IOVEC_SET_STRING(iovec[n++], source_time);
	}

	/* Note that strictly speaking storing the boot id here is
	 * redundant since the entry includes this in-line
	 * anyway. However, we need this indexed, too. */
	r = sd_id128_get_boot(&id);
	if (r >= 0) {
		sd_id128_to_string(id, boot_id + strlen("_BOOT_ID="));
		IOVEC_SET_STRING(iovec[n++], boot_id);
	}

	r = sd_id128_get_machine(&id);
	if (r >= 0) {
		sd_id128_to_string(id, machine_id + strlen("_MACHINE_ID="));
		IOVEC_SET_STRING(iovec[n++], machine_id);
	}

	t = gethostname_malloc();
	if (t) {
		x = strappenda("_HOSTNAME=", t);
		free(t);
		IOVEC_SET_STRING(iovec[n++], x);
	}

	assert(n <= m);

	if (s->split_mode == SPLIT_UID && realuid > 0)
		/* Split up strictly by any UID */
		journal_uid = realuid;
	else if (s->split_mode == SPLIT_LOGIN && realuid > 0 && owner_valid && owner > 0)
		/* Split up by login UIDs, this avoids creation of
		 * individual journals for system UIDs.  We do this
		 * only if the realuid is not root, in order not to
		 * accidentally leak privileged information to the
		 * user that is logged by a privileged process that is
		 * part of an unprivileged session.*/
		journal_uid = owner;
	else
		journal_uid = 0;

	write_to_journal(s, journal_uid, iovec, n, priority);
}

void server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...)
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
	char_array_0(buffer);
	IOVEC_SET_STRING(iovec[n++], buffer);

	if (!sd_id128_equal(message_id, SD_ID128_NULL)) {
		snprintf(mid, sizeof(mid), MESSAGE_ID(message_id));
		char_array_0(mid);
		IOVEC_SET_STRING(iovec[n++], mid);
	}

	ucred.pid = getpid();
	ucred.uid = getuid();
	ucred.gid = getgid();

	dispatch_message_real(s, iovec, n, ELEMENTSOF(iovec), &ucred, NULL, NULL, 0,
	    "systemd-journald.service", LOG_INFO, 0);
}

void server_dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m,
    struct socket_ucred *ucred, struct timeval *tv, const char *label, size_t label_len,
    const char *unit_id, int priority, pid_t object_pid)
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

	// r = cg_pid_get_path_shifted(ucred->pid, NULL, &path);
	// if (r < 0)
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

	rl = journal_rate_limit_test(s->rate_limit, path, priority & LOG_PRIMASK,
	    available_space(s, false));

	if (rl == 0)
		return;

	/* Write a suppression message if we suppressed something */
	if (rl > 1)
		server_driver_message(s, SD_MESSAGE_JOURNAL_DROPPED,
		    "Suppressed %u messages from %s", rl - 1, path);

finish:
	dispatch_message_real(s, iovec, n, m, ucred, tv, label, label_len, unit_id, priority,
	    object_pid);
}


static int system_journal_open(Server *s)
{
	int r;
	char *fn;
	sd_id128_t machine;
	char ids[33];

	r = sd_id128_get_machine(&machine);
	if (r < 0) {
		log_error("Failed to get machine id: %s", strerror(-r));
		return r;
	}

	sd_id128_to_string(machine, ids);

	if (!s->system_journal && (s->storage == STORAGE_PERSISTENT || s->storage == STORAGE_AUTO) &&
	    access(INSTALL_PKGRUNSTATE_DIR "/journal/flushed", F_OK) >= 0) {

		/* If in auto mode: first try to create the machine
		 * path, but not the prefix.
		 *
		 * If in persistent mode: create /var/log/evlog and
		 * the machine path */

		if (s->storage == STORAGE_PERSISTENT)
			(void) mkdir("/var/log/evlog/", 0755);

		fn = strappenda("/var/log/evlog/", ids);
		(void) mkdir(fn, 0755);

		fn = strappenda(fn, "/system.journal");
		r = journal_file_open_reliably(fn, O_RDWR | O_CREAT, 0640, s->compress, s->seal,
		    &s->system_metrics, s->mmap, NULL, &s->system_journal);

		if (r >= 0)
			server_fix_perms(s, s->system_journal, 0);
		else if (r < 0) {
			if (r != -ENOENT && r != -EROFS)
				log_warning("Failed to open system journal: %s", strerror(-r));

			r = 0;
		}
	}

	if (!s->runtime_journal && (s->storage != STORAGE_NONE)) {

		fn = strjoin(INSTALL_PKGRUNSTATE_DIR "/evlog/", ids, "/system.journal", NULL);
		if (!fn)
			return -ENOMEM;

		if (s->system_journal) {
			/* Try to open the runtime journal, but only
			 * if it already exists, so that we can flush
			 * it into the system journal */

			r = journal_file_open(fn, O_RDWR, 0640, s->compress, false,
			    &s->runtime_metrics, s->mmap, NULL, &s->runtime_journal);

			if (r < 0) {
				if (r != -ENOENT)
					log_warning("Failed to open runtime journal %s: %s", fn,
					    strerror(-r));

				r = 0;
			}

			free(fn);

		} else {
			/* OK, we really need the runtime journal, so create
			 * it if necessary. */

			(void) mkdir_parents(fn, 0755);
			r = journal_file_open_reliably(fn, O_RDWR | O_CREAT, 0640, s->compress,
			    false, &s->runtime_metrics, s->mmap, NULL, &s->runtime_journal);

			if (r < 0) {
				log_error("Failed to open runtime journal %s (try 2): %s", fn,
				    strerror(-r));
				free(fn);

				return r;
			}
			free(fn);
		}

		if (s->runtime_journal)
			server_fix_perms(s, s->runtime_journal, 0);
	}

	available_space(s, true);

	return r;
}

int server_flush_to_var(Server *s)
{
	sd_id128_t machine;
	sd_journal *j = NULL;
	char ts[FORMAT_TIMESPAN_MAX];
	usec_t start;
	unsigned n = 0;
	int r;

	assert(s);

	if (s->storage != STORAGE_AUTO && s->storage != STORAGE_PERSISTENT)
		return 0;

	if (!s->runtime_journal)
		return 0;

	system_journal_open(s);

	if (!s->system_journal)
		return 0;

	log_debug("Flushing to /var...");

	start = now(CLOCK_MONOTONIC);

	r = sd_id128_get_machine(&machine);
	if (r < 0)
		return r;

	r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY);
	if (r < 0) {
		log_error("Failed to read runtime journal: %s", strerror(-r));
		return r;
	}

	sd_journal_set_data_threshold(j, 0);

	SD_JOURNAL_FOREACH(j)
	{
		Object *o = NULL;
		JournalFile *f;

		f = j->current_file;
		assert(f && f->current_offset > 0);

		n++;

		r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
		if (r < 0) {
			log_error("Can't read entry: %s", strerror(-r));
			goto finish;
		}

		r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL,
		    NULL);
		if (r >= 0)
			continue;

		if (!shall_try_append_again(s->system_journal, r)) {
			log_error("Can't write entry: %s", strerror(-r));
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
		r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL,
		    NULL);
		if (r < 0) {
			log_error("Can't write entry: %s", strerror(-r));
			goto finish;
		}
	}

finish:
	journal_file_post_change(s->system_journal);

	journal_file_close(s->runtime_journal);
	s->runtime_journal = NULL;

	if (r >= 0)
		rm_rf(INSTALL_PKGRUNSTATE_DIR "/evlog", false, true, false);

	sd_journal_close(j);

	server_driver_message(s, SD_ID128_NULL,
	    "Time spent on flushing to /var is %s for %u entries.",
	    format_timespan(ts, sizeof(ts), now(CLOCK_MONOTONIC) - start, 0), n);

	return r;
}

static void sync_timer(struct ev_loop *loop, ev_timer *watch, int revents)
{
	log_debug("Got sync request from epoll.");
	server_sync(watch->data);
}

static void sigusr1_signal(struct ev_loop *loop, ev_signal *watch, int revents)
{
	Server *s = watch->data;
	log_info("Received request to flush runtime journal");
	touch(INSTALL_PKGRUNSTATE_DIR "/journal/flushed");
	server_flush_to_var(s);
	server_sync(s);
}

static void sigusr2_signal(struct ev_loop *loop, ev_signal *watch, int revents)
{
	Server *s = watch->data;
	log_info("Received request to rotate journal\n");
	server_rotate(s);
	server_vacuum(s);
}

static void sigterm_signal(struct ev_loop *loop, ev_signal *watch, int revents)
{
	Server *s = watch->data;
	log_info("Signal received, shutting down.\n");
	s->to_quit = true;
}

void process_datagram_io(struct ev_loop *evloop, ev_io *watch, int revents)
{
	Server *s = watch->data;

	assert(s);

	if (revents != EV_READ) {
		log_error("Got invalid event from epoll for %s: %" PRIx32,
		    watch == &s->native_watch ? "native fd" : "syslog fd", revents);
		return;
	}

	for (;;) {
		struct msghdr msghdr;
		struct iovec iovec;
		struct socket_ucred ucred = { -1, -1, -1 };
		struct timeval *tv = NULL;
		struct cmsghdr *cmsg;
		char *label = NULL;
		size_t label_len = 0;
		union {
			struct cmsghdr cmsghdr;

			/* We use NAME_MAX space for the
				 * SELinux label here. The kernel
				 * currently enforces no limit, but
				 * according to suggestions from the
				 * SELinux people this will change and
				 * it will probably be identical to
				 * NAME_MAX. For now we use that, but
				 * this should be updated one day when
				 * the final limit is known.*/
			uint8_t buf[
#ifdef CMSG_CREDS_STRUCT_SIZE
			    CMSG_SPACE(CMSG_CREDS_STRUCT_SIZE) +
#endif
			    CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(int)) /* fds */
#ifdef SCM_SECURITY
			    + CMSG_SPACE(NAME_MAX) /* selinux label */
#endif
			];
		} control;
		ssize_t n;
		int v;
		int *fds = NULL;
		unsigned n_fds = 0;

		if (socket_fionread(watch->fd, &v) < 0) {
			log_error("socket_fionread failed: %m");
			return;
		}

		if (s->buffer_size < (size_t) v) {
			void *b;
			size_t l;

			l = MAX(LINE_MAX + (size_t) v, s->buffer_size * 2);
			b = realloc(s->buffer, l + 1);

			if (!b) {
				log_error("Couldn't increase buffer.");
				return;
			}

			s->buffer_size = l;
			s->buffer = b;
		}

		zero(iovec);
		iovec.iov_base = s->buffer;
		iovec.iov_len = s->buffer_size;

		zero(control);
		zero(msghdr);
		msghdr.msg_iov = &iovec;
		msghdr.msg_iovlen = 1;
		msghdr.msg_control = &control;
		msghdr.msg_controllen = sizeof(control);

#ifndef MSG_CMSG_CLOEXEC // FIXME: #28
#define MSG_CMSG_CLOEXEC 0
#endif

		n = recvmsg(watch->fd, &msghdr, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
		if (n < 0) {

			if (errno == EINTR || errno == EAGAIN)
				return;

			log_error("recvmsg() failed: %m");
			return;
		}

		for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {

			if (cmsg_readucred(cmsg, &ucred))
				;
#ifdef SCM_SECURITY
			else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_SECURITY) {
				label = (char *) CMSG_DATA(cmsg);
				label_len = cmsg->cmsg_len - CMSG_LEN(0);
			}
#endif
			else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP &&
			    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
				tv = (struct timeval *) CMSG_DATA(cmsg);
			else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				fds = (int *) CMSG_DATA(cmsg);
				n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			}
		}

		if (watch == &s->syslog_watch) {
			if (n > 0 && n_fds == 0) {
				s->buffer[n] = 0;
				server_process_syslog_message(s, strstrip(s->buffer), &ucred, tv,
				    label, label_len);
			} else if (n_fds > 0)
				log_warning("Got file descriptors via syslog socket. Ignoring.");

		} else {
			if (n > 0 && n_fds == 0)
				server_process_native_message(s, s->buffer, n, &ucred, tv, label,
				    label_len);
			else if (n == 0 && n_fds == 1)
				server_process_native_file(s, fds[0], &ucred, tv, label, label_len);
			else if (n_fds > 0)
				log_warning(
				    "Got too many file descriptors via native socket. Ignoring.");
		}

		close_many(fds, n_fds);
	}
}

static int open_signalfd(Server *s)
{
	sigset_t mask;
	int r;

	assert(s);

	/*assert_se(sigemptyset(&mask) == 0);
	sigset_add_many(&mask, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, -1);
	assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);*/

	ev_signal_init(&s->sigusr1_watch, sigusr1_signal, SIGUSR1);
	ev_signal_init(&s->sigusr2_watch, sigusr2_signal, SIGUSR2);
	ev_signal_init(&s->sigint_watch, sigterm_signal, SIGINT);
	ev_signal_init(&s->sigterm_watch, sigterm_signal, SIGTERM);
	s->sigusr1_watch.data = s;
	s->sigusr2_watch.data =s;
	s->sigint_watch.data =s;
	s->sigterm_watch.data =s;

	r = ev_signal_start(s->evloop, &s->sigusr1_watch);
	if (r < 0)
		goto fail;
	r = ev_signal_start(s->evloop, &s->sigusr2_watch);
	if (r < 0)
		goto fail;
	r = ev_signal_start(s->evloop, &s->sigint_watch);
	if (r < 0)
		goto fail;
	r = ev_signal_start(s->evloop, &s->sigterm_watch);
	if (r < 0)
		goto fail;

	return 0;

fail:
	log_error("Failed to add signal to event loop: %m\n");
	return -errno;
}

static int server_parse_proc_cmdline(Server *s)
{
	_cleanup_free_ char *line = NULL;
	char *w, *state;
	int r;
	size_t l;

	if (detect_container(NULL) > 0)
		return 0;

	r = read_one_line_file("/proc/cmdline", &line);
	if (r < 0) {
		log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
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
				log_warning("Failed to parse forward to syslog switch %s. Ignoring.",
				    word + 35);
			else
				s->forward_to_syslog = r;
		} else if (startswith(word, "systemd.journald.forward_to_kmsg=")) {
			r = parse_boolean(word + 33);
			if (r < 0)
				log_warning("Failed to parse forward to kmsg switch %s. Ignoring.",
				    word + 33);
			else
				s->forward_to_kmsg = r;
		} else if (startswith(word, "systemd.journald.forward_to_console=")) {
			r = parse_boolean(word + 36);
			if (r < 0)
				log_warning("Failed to parse forward to console switch %s. Ignoring.",
				    word + 36);
			else
				s->forward_to_console = r;
		} else if (startswith(word, "systemd.journald"))
			log_warning("Invalid systemd.journald parameter. Ignoring.");
	}

	return 0;
}

static int server_parse_config_file(Server *s)
{
	static const char fn[] = INSTALL_PKGSYSCONF_DIR "/journald.conf";
	_cleanup_fclose_ FILE *f = NULL;
	int r;

	assert(s);

	f = fopen(fn, "re");
	if (!f) {
		if (errno == ENOENT)
			return 0;

		log_warning("Failed to open configuration file %s: %m", fn);
		return -errno;
	}

	r = config_parse(NULL, fn, f, "Journal\0", config_item_perf_lookup,
	    (void *) journald_gperf_lookup, false, false, s);
	if (r < 0)
		log_warning("Failed to parse configuration file: %s", strerror(-r));

	return r;
}

int server_schedule_sync(Server *s, int priority)
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

	if (s->sync_interval_usec) {
		ev_timer_init(&s->sync_timer_watch, sync_timer,
		    s->sync_interval_usec / USEC_PER_SEC, 0.);
		s->sync_timer_watch.data = s;
		r = ev_timer_start(s->evloop, &s->sync_timer_watch);
		if (r < 0)
			return -errno;
	}

	s->sync_scheduled = true;

	return 0;
}

int server_init(Server *s)
{
	int n, r, fd;

	assert(s);

	zero(*s);
	ev_timer_zero(s->sync_timer_watch);
	ev_io_zero(s->syslog_watch);
	ev_io_zero(s->native_watch);
	ev_io_zero(s->stdout_watch);
	ev_io_zero(s->dev_kmsg_watch);
	s->compress = true;
	s->seal = true;

	s->sync_interval_usec = DEFAULT_SYNC_INTERVAL_USEC;
	s->sync_scheduled = false;

	s->rate_limit_interval = DEFAULT_RATE_LIMIT_INTERVAL;
	s->rate_limit_burst = DEFAULT_RATE_LIMIT_BURST;

	s->forward_to_syslog = true;

	s->max_file_usec = DEFAULT_MAX_FILE_USEC;

	s->max_level_store = LOG_DEBUG;
	s->max_level_syslog = LOG_DEBUG;
	s->max_level_kmsg = LOG_NOTICE;
	s->max_level_console = LOG_INFO;

	memset(&s->system_metrics, 0xFF, sizeof(s->system_metrics));
	memset(&s->runtime_metrics, 0xFF, sizeof(s->runtime_metrics));

	server_parse_config_file(s);
	server_parse_proc_cmdline(s);
	if (!!s->rate_limit_interval ^ !!s->rate_limit_burst) {
		log_debug("Setting both rate limit interval and burst from %llu,%u to 0,0",
		    (long long unsigned) s->rate_limit_interval, s->rate_limit_burst);
		s->rate_limit_interval = s->rate_limit_burst = 0;
	}

	mkdir_p(INSTALL_PKGRUNSTATE_DIR "/journal", 0755);

	s->user_journals = hashmap_new(trivial_hash_func, trivial_compare_func);
	if (!s->user_journals)
		return log_oom();

	s->mmap = mmap_cache_new();
	if (!s->mmap)
		return log_oom();

	s->evloop = ev_default_loop(0);
	if (s->evloop == NULL) {
		log_error("Failed to create event loop object: %m");
		return -errno;
	}

	n = sd_listen_fds(true);
	if (n < 0) {
		log_error("Failed to read listening file descriptors from environment: %s",
		    strerror(-n));
		return n;
	}

	for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {

		if (sd_is_socket_unix(fd, SOCK_DGRAM, -1,
			INSTALL_PKGRUNSTATE_DIR "/journal/socket", 0) > 0) {

			if (s->native_watch.fd >= 0) {
				log_error("Too many native sockets passed.");
				return -EINVAL;
			}

			s->native_watch.fd = fd;

		} else if (sd_is_socket_unix(fd, SOCK_STREAM, 1,
			       INSTALL_PKGRUNSTATE_DIR "/journal/stdout", 0) > 0) {

			if (s->stdout_watch.fd >= 0) {
				log_error("Too many stdout sockets passed.");
				return -EINVAL;
			}

			s->stdout_watch.fd = fd;

		} else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/dev/log", 0) > 0) {

			if (s->syslog_watch.fd >= 0) {
				log_error("Too many /dev/log sockets passed.");
				return -EINVAL;
			}

			s->syslog_watch.fd = fd;

		} else {
			log_error("Unknown socket passed.");
			return -EINVAL;
		}
	}

	r = server_open_syslog_socket(s);
	if (r < 0)
		return r;

	r = server_open_native_socket(s);
	if (r < 0)
		return r;

	r = server_open_stdout_socket(s);
	if (r < 0)
		return r;

	r = server_open_dev_kmsg(s);
	if (r < 0)
		return r;

	r = server_open_kernel_seqnum(s);
	if (r < 0)
		return r;

	r = open_signalfd(s);
	if (r < 0)
		return r;

#ifdef Use_UDev
	s->udev = udev_new();
	if (!s->udev)
		return -ENOMEM;
#endif

	s->rate_limit = journal_rate_limit_new(s->rate_limit_interval, s->rate_limit_burst);
	if (!s->rate_limit)
		return -ENOMEM;

	r = system_journal_open(s);
	if (r < 0)
		return r;

	return 0;
}

void server_maybe_append_tags(Server *s)
{
#ifdef HAVE_GCRYPT
	JournalFile *f;
	Iterator i;
	usec_t n;

	n = now(CLOCK_REALTIME);

	if (s->system_journal)
		journal_file_maybe_append_tag(s->system_journal, n);

	HASHMAP_FOREACH (f, s->user_journals, i)
		journal_file_maybe_append_tag(f, n);
#endif
}

void server_done(Server *s)
{
	JournalFile *f;
	assert(s);

	while (s->stdout_streams)
		stdout_stream_free(s->stdout_streams);

	if (s->system_journal)
		journal_file_close(s->system_journal);

	if (s->runtime_journal)
		journal_file_close(s->runtime_journal);

	while ((f = hashmap_steal_first(s->user_journals)))
		journal_file_close(f);

	hashmap_free(s->user_journals);

	ev_signal_stop(s->evloop, &s->sigusr1_watch);
	ev_io_stop(s->evloop, &s->syslog_watch);
	ev_io_stop(s->evloop, &s->native_watch);
	ev_io_stop(s->evloop, &s->stdout_watch);
	ev_io_stop(s->evloop, &s->dev_kmsg_watch);
	ev_timer_stop(s->evloop, &s->sync_timer_watch);

	if (s->rate_limit)
		journal_rate_limit_free(s->rate_limit);

	if (s->kernel_seqnum)
		munmap(s->kernel_seqnum, sizeof(uint64_t));

	free(s->buffer);
	free(s->tty_path);

	if (s->mmap)
		mmap_cache_unref(s->mmap);

#ifdef Use_UDev
	if (s->udev)
		udev_unref(s->udev);
#endif
}
