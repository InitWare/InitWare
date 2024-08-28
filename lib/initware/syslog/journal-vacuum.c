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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bsdxattr.h"
#include "format-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-vacuum.h"
#include "sd-id128.h"
#include "util.h"

struct vacuum_info {
	uint64_t usage;
	char *filename;

	uint64_t realtime;
	sd_id128_t seqnum_id;
	uint64_t seqnum;

	bool have_seqnum;
};

static int
vacuum_compare(const void *_a, const void *_b)
{
	const struct vacuum_info *a, *b;

	a = _a;
	b = _b;

	if (a->have_seqnum && b->have_seqnum &&
		sd_id128_equal(a->seqnum_id, b->seqnum_id)) {
		if (a->seqnum < b->seqnum)
			return -1;
		else if (a->seqnum > b->seqnum)
			return 1;
		else
			return 0;
	}

	if (a->realtime < b->realtime)
		return -1;
	else if (a->realtime > b->realtime)
		return 1;
	else if (a->have_seqnum && b->have_seqnum)
		return memcmp(&a->seqnum_id, &b->seqnum_id, 16);
	else
		return strcmp(a->filename, b->filename);
}

static void
patch_realtime(const char *dir, const char *fn, const struct stat *st,
	unsigned long long *realtime)
{
	_cleanup_free_ const char *path = NULL;
	usec_t x, crtime = 0;

	/* The timestamp was determined by the file name, but let's
         * see if the file might actually be older than the file name
         * suggested... */

	assert(dir);
	assert(fn);
	assert(st);
	assert(realtime);

	x = timespec_load(&st->st_ctim);
	if (x > 0 && x != USEC_INFINITY && x < *realtime)
		*realtime = x;

	x = timespec_load(&st->st_atim);
	if (x > 0 && x != USEC_INFINITY && x < *realtime)
		*realtime = x;

	x = timespec_load(&st->st_mtim);
	if (x > 0 && x != USEC_INFINITY && x < *realtime)
		*realtime = x;

	/* Let's read the original creation time, if possible. Ideally
         * we'd just query the creation time the FS might provide, but
         * unfortunately there's currently no sane API to query
         * it. Hence let's implement this manually... */

	/* Unfortunately there is is not fgetxattrat(), so we need to
         * go via path here. :-( */

	path = strjoin(dir, "/", fn, NULL);
	if (!path)
		return;

	if (path_getcrtime(path, &crtime) >= 0) {
		if (crtime < *realtime)
			*realtime = crtime;
	}
}

static int
journal_file_empty(int dir_fd, const char *name)
{
	_cleanup_close_ int fd;
	struct stat st;
	le64_t n_entries;
	ssize_t n;

	fd = openat(dir_fd, name,
		O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) < 0)
		return -errno;

	/* If an offline file doesn't even have a header we consider it empty */
	if (st.st_size < (off_t)sizeof(Header))
		return 1;

	/* If the number of entries is empty, we consider it empty, too */
	n = pread(fd, &n_entries, sizeof(n_entries),
		offsetof(Header, n_entries));
	if (n < 0)
		return -errno;
	if (n != sizeof(n_entries))
		return -EIO;

	return le64toh(n_entries) <= 0;
}

int
journal_directory_vacuum(const char *directory, uint64_t max_use,
	usec_t max_retention_usec, usec_t *oldest_usec, bool verbose)
{
	_cleanup_closedir_ DIR *d = NULL;
	int r = 0;
	struct vacuum_info *list = NULL;
	unsigned n_list = 0, i;
	uint64_t sum = 0, freed = 0;
	usec_t retention_limit = 0;
	char sbytes[FORMAT_BYTES_MAX];

	assert(directory);

	if (max_use <= 0 && max_retention_usec <= 0)
		return 0;

	if (max_retention_usec > 0) {
		retention_limit = now(CLOCK_REALTIME);
		if (retention_limit > max_retention_usec)
			retention_limit -= max_retention_usec;
		else
			max_retention_usec = retention_limit = 0;
	}

	d = opendir(directory);
	if (!d)
		return -errno;

	for (;;) {
		struct dirent *de;
		size_t q;
		struct stat st;
		char *p;
		unsigned long long seqnum = 0, realtime;
		sd_id128_t seqnum_id;
		bool have_seqnum;

		errno = 0;
		de = readdir(d);
		if (!de && errno != 0) {
			r = -errno;
			goto finish;
		}

		if (!de)
			break;

		if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
			continue;

		if (!S_ISREG(st.st_mode))
			continue;

		q = strlen(de->d_name);

		if (endswith(de->d_name, ".journal")) {
			/* Vacuum archived files */

			if (q < 1 + 32 + 1 + 16 + 1 + 16 + 8)
				continue;

			if (de->d_name[q - 8 - 16 - 1] != '-' ||
				de->d_name[q - 8 - 16 - 1 - 16 - 1] != '-' ||
				de->d_name[q - 8 - 16 - 1 - 16 - 1 - 32 - 1] !=
					'@')
				continue;

			p = strdup(de->d_name);
			if (!p) {
				r = -ENOMEM;
				goto finish;
			}

			de->d_name[q - 8 - 16 - 1 - 16 - 1] = 0;
			if (sd_id128_from_string(de->d_name + q - 8 - 16 - 1 -
					    16 - 1 - 32,
				    &seqnum_id) < 0) {
				free(p);
				continue;
			}

			if (sscanf(de->d_name + q - 8 - 16 - 1 - 16,
				    "%16llx-%16llx.journal", &seqnum,
				    &realtime) != 2) {
				free(p);
				continue;
			}

			have_seqnum = true;

		} else if (endswith(de->d_name, ".journal~")) {
			unsigned long long tmp;

			/* Vacuum corrupted files */

			if (q < 1 + 16 + 1 + 16 + 8 + 1)
				continue;

			if (de->d_name[q - 1 - 8 - 16 - 1] != '-' ||
				de->d_name[q - 1 - 8 - 16 - 1 - 16 - 1] != '@')
				continue;

			p = strdup(de->d_name);
			if (!p) {
				r = -ENOMEM;
				goto finish;
			}

			if (sscanf(de->d_name + q - 1 - 8 - 16 - 1 - 16,
				    "%16llx-%16llx.journal~", &realtime,
				    &tmp) != 2) {
				free(p);
				continue;
			}

			have_seqnum = false;
		} else
			/* We do not vacuum active files or unknown files! */
			continue;

		if (journal_file_empty(dirfd(d), p)) {
			/* Always vacuum empty non-online files. */

			uint64_t size = 512UL * (uint64_t)st.st_blocks;

			if (unlinkat(dirfd(d), p, 0) >= 0) {
				log_full(verbose ? LOG_INFO : LOG_DEBUG,
					"Deleted empty archived journal %s/%s (%s).",
					directory, p,
					format_bytes(sbytes, sizeof(sbytes),
						size));
				freed += size;
			} else if (errno != ENOENT)
				log_warning_errno(errno,
					"Failed to delete empty archived journal %s/%s: %m",
					directory, p);

			free(p);
			continue;
		}

		patch_realtime(directory, p, &st, &realtime);

		if (!GREEDY_REALLOC(list, n_list + 1)) {
			free(p);
			r = -ENOMEM;
			goto finish;
		}

		list[n_list].filename = p;
		list[n_list].usage = 512UL * (uint64_t)st.st_blocks;
		list[n_list].seqnum = seqnum;
		list[n_list].realtime = realtime;
		list[n_list].seqnum_id = seqnum_id;
		list[n_list].have_seqnum = have_seqnum;

		sum += list[n_list].usage;

		n_list++;
	}

	qsort_safe(list, n_list, sizeof(struct vacuum_info), vacuum_compare);

	for (i = 0; i < n_list; i++) {
		if ((max_retention_usec <= 0 ||
			    list[i].realtime >= retention_limit) &&
			(max_use <= 0 || sum <= max_use))
			break;

		if (unlinkat(dirfd(d), list[i].filename, 0) >= 0) {
			log_full(verbose ? LOG_INFO : LOG_DEBUG,
				"Deleted archived journal %s/%s (%s).",
				directory, list[i].filename,
				format_bytes(sbytes, sizeof(sbytes),
					list[i].usage));
			freed += list[i].usage;

			if (list[i].usage < sum)
				sum -= list[i].usage;
			else
				sum = 0;

		} else if (errno != ENOENT)
			log_warning_errno(errno,
				"Failed to delete archived journal %s/%s: %m",
				directory, list[i].filename);
	}

	if (oldest_usec && i < n_list &&
		(*oldest_usec == 0 || list[i].realtime < *oldest_usec))
		*oldest_usec = list[i].realtime;

finish:
	for (i = 0; i < n_list; i++)
		free(list[i].filename);
	free(list);

	log_full(verbose ? LOG_INFO : LOG_DEBUG,
		"Vacuuming done, freed %s of archived journals on disk.",
		format_bytes(sbytes, sizeof(sbytes), freed));

	return r;
}
