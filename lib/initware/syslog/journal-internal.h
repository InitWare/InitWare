#pragma once

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
#include <inttypes.h>
#include <stdbool.h>

#include "systemd/sd-id128.h"

#include "hashmap.h"
#include "journal-def.h"
#include "journal-file.h"
#include "list.h"
#include "prioq.h"
#include "ratelimit.h"
#include "sd-journal.h"
#include "set.h"

typedef struct Match Match;
typedef struct Location Location;
typedef struct Directory Directory;

typedef enum MatchType {
        MATCH_DISCRETE,
        MATCH_OR_TERM,
        MATCH_AND_TERM
} MatchType;

struct Match {
        MatchType type;
        Match *parent;
        LIST_FIELDS(Match, matches);

        /* For concrete matches */
        char *data;
        size_t size;
        uint64_t hash; /* old-style jenkins hash. New-style siphash is different per file, hence won't be cached here */

        /* For terms */
        LIST_HEAD(Match, matches);
};

struct Location {
	LocationType type;

	bool seqnum_set;
	bool realtime_set;
	bool monotonic_set;
	bool xor_hash_set;

	uint64_t seqnum;
	sd_id128_t seqnum_id;

	uint64_t realtime;

	uint64_t monotonic;
	sd_id128_t boot_id;

	uint64_t xor_hash;
};

struct Directory {
        sd_journal *journal;
        char *path;
        int wd;
        bool is_root;
        unsigned last_seen_generation;
};

// struct sd_journal {
// 	char *path;
// 	char *prefix;

// 	OrderedHashmap *files;
// 	MMapCache *mmap;

// 	Location current_location;

// 	JournalFile *current_file;
// 	uint64_t current_field;

// 	Match *level0, *level1, *level2;

// 	pid_t original_pid;

// 	int inotify_fd;
// 	unsigned current_invalidate_counter, last_invalidate_counter;
// 	usec_t last_process_usec;
// 	unsigned generation;

// 	char *unique_field;
// 	JournalFile *unique_file;
// 	uint64_t unique_offset;

// 	int flags;

// 	bool on_network;
// 	bool no_new_files;
// 	bool unique_file_lost; /* File we were iterating over got
//                                   removed, and there were no more
//                                   files, so sd_j_enumerate_unique
//                                   will return a value equal to 0. */
// 	bool has_runtime_files: 1;
// 	bool has_persistent_files: 1;

// 	size_t data_threshold;

// 	Hashmap *directories_by_path;
// 	Hashmap *directories_by_wd;

// 	Hashmap *errors;
// };

typedef struct NewestByBootId {
        sd_id128_t boot_id;
        Prioq *prioq; /* JournalFile objects ordered by monotonic timestamp of last update. */
} NewestByBootId;

struct sd_journal {
        int toplevel_fd;

        char *path;
        char *prefix;
        char *namespace;

        OrderedHashmap *files;
        IteratedCache *files_cache;
        MMapCache *mmap;

        /* a bisectable array of NewestByBootId, ordered by boot id. */
        NewestByBootId *newest_by_boot_id;
        size_t n_newest_by_boot_id;

        Location current_location;

        JournalFile *current_file;
        uint64_t current_field;

        Match *level0, *level1, *level2;
        Set *exclude_syslog_identifiers;

        uint64_t origin_id;

        int inotify_fd;
        unsigned current_invalidate_counter, last_invalidate_counter;
        usec_t last_process_usec;
        unsigned generation;

        /* Iterating through unique fields and their data values */
        char *unique_field;
        JournalFile *unique_file;
        uint64_t unique_offset;

        /* Iterating through known fields */
        JournalFile *fields_file;
        uint64_t fields_offset;
        uint64_t fields_hash_table_index;
        char *fields_buffer;

        int flags;

        bool on_network:1;
        bool no_new_files:1;
        bool no_inotify:1;
        bool unique_file_lost:1; /* File we were iterating over got
                                    removed, and there were no more
                                    files, so sd_j_enumerate_unique
                                    will return a value equal to 0. */
        bool fields_file_lost:1;
        bool has_runtime_files:1;
        bool has_persistent_files:1;

        size_t data_threshold;

        Hashmap *directories_by_path;
        Hashmap *directories_by_wd;

        Hashmap *errors;
};

#define JOURNAL_LOG_RATELIMIT ((const RateLimit) { .interval = 60 * USEC_PER_SEC, .burst = 3 })

char *journal_make_match_string(sd_journal *j);
void journal_print_header(sd_journal *j);

int journal_add_match_pair(sd_journal *j, const char *field, const char *value);
int journal_add_matchf(sd_journal *j, const char *format, ...) _printf_(2, 3);

// DEFINE_TRIVIAL_CLEANUP_FUNC(sd_journal *, sd_journal_close);
// #define _cleanup_journal_close_ _cleanup_(sd_journal_closep)

#define JOURNAL_FOREACH_DATA_RETVAL(j, data, l, retval)                        \
	for (sd_journal_restart_data(j);                                       \
		((retval) = sd_journal_enumerate_data((j), &(data), &(l))) >   \
		0;)
