/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "catalog.h"
#include "conf-files.h"
#include "hashmap.h"
#include "log.h"
#include "mkdir.h"
#include "sd-id128.h"
#include "sparse-endian.h"
#include "strbuf.h"
#include "strv.h"
#include "strxcpyx.h"
#include "util.h"

const char *const catalog_file_dirs[] = {
#ifdef Use_SystemdCompat
	"/usr/local/lib/systemd/catalog/",
#endif
	INSTALL_PKGLIB_DIR "/catalog/", NULL
};

#define CATALOG_SIGNATURE                              \
	(uint8_t[])                                    \
	{                                              \
		'R', 'H', 'H', 'H', 'K', 'S', 'L', 'P' \
	}

typedef struct CatalogHeader {
	uint8_t signature[8]; /* "RHHHKSLP" */
	le32_t compatible_flags;
	le32_t incompatible_flags;
	le64_t header_size;
	le64_t n_items;
	le64_t catalog_item_size;
} CatalogHeader;

typedef struct CatalogItem {
	sd_id128_t id;
	char language[32];
	le64_t offset;
} CatalogItem;

unsigned catalog_hash_func(const void *p)
{
	const CatalogItem *i = p;

	assert_cc(sizeof(unsigned) == sizeof(uint8_t) * 4);

	return (((unsigned) i->id.bytes[0] << 24) | ((unsigned) i->id.bytes[1] << 16) |
		   ((unsigned) i->id.bytes[2] << 8) | ((unsigned) i->id.bytes[3])) ^
	    (((unsigned) i->id.bytes[4] << 24) | ((unsigned) i->id.bytes[5] << 16) |
		((unsigned) i->id.bytes[6] << 8) | ((unsigned) i->id.bytes[7])) ^
	    (((unsigned) i->id.bytes[8] << 24) | ((unsigned) i->id.bytes[9] << 16) |
		((unsigned) i->id.bytes[10] << 8) | ((unsigned) i->id.bytes[11])) ^
	    (((unsigned) i->id.bytes[12] << 24) | ((unsigned) i->id.bytes[13] << 16) |
		((unsigned) i->id.bytes[14] << 8) | ((unsigned) i->id.bytes[15])) ^
	    string_hash_func(i->language);
}

int catalog_compare_func(const void *a, const void *b)
{
	const CatalogItem *i = a, *j = b;
	unsigned k;

	for (k = 0; k < ELEMENTSOF(j->id.bytes); k++) {
		if (i->id.bytes[k] < j->id.bytes[k])
			return -1;
		if (i->id.bytes[k] > j->id.bytes[k])
			return 1;
	}

	return strcmp(i->language, j->language);
}

static int finish_item(Hashmap *h, struct strbuf *sb, sd_id128_t id, const char *language,
    const char *payload)
{

	ssize_t offset;
	_cleanup_free_ CatalogItem *i = NULL;
	int r;

	assert(h);
	assert(sb);
	assert(payload);

	offset = strbuf_add_string(sb, payload, strlen(payload));
	if (offset < 0)
		return log_oom();

	i = new0(CatalogItem, 1);
	if (!i)
		return log_oom();

	i->id = id;
	strscpy(i->language, sizeof(i->language), language);
	i->offset = htole64((uint64_t) offset);

	r = hashmap_put(h, i, i);
	if (r == -EEXIST) {
		log_warning("Duplicate entry for " SD_ID128_FORMAT_STR ".%s, ignoring.",
		    SD_ID128_FORMAT_VAL(id), language ? language : "C");
		return 0;
	} else if (r < 0)
		return r;

	i = NULL;
	return 0;
}

int catalog_import_file(Hashmap *h, struct strbuf *sb, const char *path)
{
	_cleanup_fclose_ FILE *f = NULL;
	_cleanup_free_ char *payload = NULL;
	unsigned n = 0;
	sd_id128_t id;
	char language[32];
	bool got_id = false, empty_line = true;
	int r;

	assert(h);
	assert(sb);
	assert(path);

	f = fopen(path, "re");
	if (!f) {
		log_error("Failed to open file %s: %m", path);
		return -errno;
	}

	for (;;) {
		char line[LINE_MAX];
		size_t a, b, c;
		char *t;

		if (!fgets(line, sizeof(line), f)) {
			if (feof(f))
				break;

			log_error("Failed to read file %s: %m", path);
			return -errno;
		}

		n++;

		truncate_nl(line);

		if (line[0] == 0) {
			empty_line = true;
			continue;
		}

		if (strchr(COMMENTS "\n", line[0]))
			continue;

		if (empty_line && strlen(line) >= 2 + 1 + 32 && line[0] == '-' && line[1] == '-' &&
		    line[2] == ' ' && (line[2 + 1 + 32] == ' ' || line[2 + 1 + 32] == '\0')) {

			bool with_language;
			sd_id128_t jd;

			/* New entry */

			with_language = line[2 + 1 + 32] != '\0';
			line[2 + 1 + 32] = '\0';

			if (sd_id128_from_string(line + 2 + 1, &jd) >= 0) {

				if (got_id) {
					r = finish_item(h, sb, id, language, payload);
					if (r < 0)
						return r;
				}

				if (with_language) {
					t = strstrip(line + 2 + 1 + 32 + 1);

					c = strlen(t);
					if (c <= 0) {
						log_error("[%s:%u] Language too short.", path, n);
						return -EINVAL;
					}
					if (c > sizeof(language) - 1) {
						log_error("[%s:%u] language too long.", path, n);
						return -EINVAL;
					}

					strscpy(language, sizeof(language), t);
				} else
					language[0] = '\0';

				got_id = true;
				empty_line = false;
				id = jd;

				if (payload)
					payload[0] = '\0';

				continue;
			}
		}

		/* Payload */
		if (!got_id) {
			log_error("[%s:%u] Got payload before ID.", path, n);
			return -EINVAL;
		}

		a = payload ? strlen(payload) : 0;
		b = strlen(line);

		c = a + (empty_line ? 1 : 0) + b + 1 + 1;
		t = realloc(payload, c);
		if (!t)
			return log_oom();

		if (empty_line) {
			t[a] = '\n';
			memcpy(t + a + 1, line, b);
			t[a + b + 1] = '\n';
			t[a + b + 2] = 0;
		} else {
			memcpy(t + a, line, b);
			t[a + b] = '\n';
			t[a + b + 1] = 0;
		}

		payload = t;
		empty_line = false;
	}

	if (got_id) {
		r = finish_item(h, sb, id, language, payload);
		if (r < 0)
			return r;
	}

	return 0;
}

static long write_catalog(const char *database, Hashmap *h, struct strbuf *sb, CatalogItem *items,
    size_t n)
{
	CatalogHeader header;
	_cleanup_fclose_ FILE *w = NULL;
	int r;
	_cleanup_free_ char *d, *p = NULL;
	size_t k;

	d = dirname_malloc(database);
	if (!d)
		return log_oom();

	r = mkdir_p(d, 0775);
	if (r < 0) {
		log_error("Recursive mkdir %s: %s", d, strerror(-r));
		return r;
	}

	r = fopen_temporary(database, &w, &p);
	if (r < 0) {
		log_error("Failed to open database for writing: %s: %s", database, strerror(-r));
		return r;
	}

	zero(header);
	memcpy(header.signature, (CATALOG_SIGNATURE), sizeof(header.signature));
	header.header_size = htole64(ALIGN_TO(sizeof(CatalogHeader), 8));
	header.catalog_item_size = htole64(sizeof(CatalogItem));
	header.n_items = htole64(hashmap_size(h));

	r = -EIO;

	k = fwrite(&header, 1, sizeof(header), w);
	if (k != sizeof(header)) {
		log_error("%s: failed to write header.", p);
		goto error;
	}

	k = fwrite(items, 1, n * sizeof(CatalogItem), w);
	if (k != n * sizeof(CatalogItem)) {
		log_error("%s: failed to write database.", p);
		goto error;
	}

	k = fwrite(sb->buf, 1, sb->len, w);
	if (k != sb->len) {
		log_error("%s: failed to write strings.", p);
		goto error;
	}

	fflush(w);

	if (ferror(w)) {
		log_error("%s: failed to write database.", p);
		goto error;
	}

	fchmod(fileno(w), 0644);

	if (rename(p, database) < 0) {
		log_error("rename (%s -> %s) failed: %m", p, database);
		r = -errno;
		goto error;
	}

	return ftell(w);

error:
	unlink(p);
	return r;
}

int catalog_update(const char *database, const char *root, const char *const *dirs)
{
	_cleanup_strv_free_ char **files = NULL;
	char **f;
	struct strbuf *sb = NULL;
	_cleanup_hashmap_free_free_ Hashmap *h = NULL;
	_cleanup_free_ CatalogItem *items = NULL;
	CatalogItem *i;
	Iterator j;
	unsigned n;
	long r;

	h = hashmap_new(catalog_hash_func, catalog_compare_func);
	sb = strbuf_new();

	if (!h || !sb) {
		r = log_oom();
		goto finish;
	}

	r = conf_files_list_strv(&files, ".catalog", root, dirs);
	if (r < 0) {
		log_error("Failed to get catalog files: %s", strerror(-r));
		goto finish;
	}

	STRV_FOREACH (f, files) {
		log_debug("Reading file '%s'", *f);
		r = catalog_import_file(h, sb, *f);
		if (r < 0) {
			log_error("Failed to import file '%s': %s.", *f, strerror(-r));
			goto finish;
		}
	}

	if (hashmap_size(h) <= 0) {
		log_info("No items in catalog.");
		goto finish;
	} else
		log_debug("Found %u items in catalog.", hashmap_size(h));

	strbuf_complete(sb);

	items = new (CatalogItem, hashmap_size(h));
	if (!items) {
		r = log_oom();
		goto finish;
	}

	n = 0;
	HASHMAP_FOREACH (i, h, j) {
		log_debug("Found " SD_ID128_FORMAT_STR ", language %s", SD_ID128_FORMAT_VAL(i->id),
		    isempty(i->language) ? "C" : i->language);
		items[n++] = *i;
	}

	assert(n == hashmap_size(h));
	qsort_safe(items, n, sizeof(CatalogItem), catalog_compare_func);

	r = write_catalog(database, h, sb, items, n);
	if (r < 0)
		log_error("Failed to write %s: %s", database, strerror(-r));
	else
		log_debug("%s: wrote %u items, with %zu bytes of strings, %ld total size.",
		    database, n, sb->len, r);

finish:
	if (sb)
		strbuf_cleanup(sb);

	return r < 0 ? r : 0;
}

static int open_mmap(const char *database, int *_fd, struct stat *_st, void **_p)
{
	const CatalogHeader *h;
	int fd;
	void *p;
	struct stat st;

	assert(_fd);
	assert(_st);
	assert(_p);

	fd = open(database, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) < 0) {
		safe_close(fd);
		return -errno;
	}

	if (st.st_size < (off_t) sizeof(CatalogHeader)) {
		safe_close(fd);
		return -EINVAL;
	}

	p = mmap(NULL, PAGE_ALIGN(st.st_size), PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		safe_close(fd);
		return -errno;
	}

	h = p;
	if (memcmp(h->signature, CATALOG_SIGNATURE, sizeof(h->signature)) != 0 ||
	    le64toh(h->header_size) < sizeof(CatalogHeader) ||
	    le64toh(h->catalog_item_size) < sizeof(CatalogItem) || h->incompatible_flags != 0 ||
	    le64toh(h->n_items) <= 0 ||
	    st.st_size < (off_t) (le64toh(h->header_size) +
			     le64toh(h->catalog_item_size) * le64toh(h->n_items))) {
		safe_close(fd);
		munmap(p, st.st_size);
		return -EBADMSG;
	}

	*_fd = fd;
	*_st = st;
	*_p = p;

	return 0;
}

static const char *find_id(void *p, sd_id128_t id)
{
	CatalogItem key, *f = NULL;
	const CatalogHeader *h = p;
	const char *loc;

	zero(key);
	key.id = id;

	loc = setlocale(LC_MESSAGES, NULL);
	if (loc && loc[0] && !streq(loc, "C") && !streq(loc, "POSIX")) {
		strncpy(key.language, loc, sizeof(key.language));
		key.language[strcspn(key.language, ".@")] = 0;

		f = bsearch(&key, (const uint8_t *) p + le64toh(h->header_size),
		    le64toh(h->n_items), le64toh(h->catalog_item_size), catalog_compare_func);
		if (!f) {
			char *e;

			e = strchr(key.language, '_');
			if (e) {
				*e = 0;
				f = bsearch(&key, (const uint8_t *) p + le64toh(h->header_size),
				    le64toh(h->n_items), le64toh(h->catalog_item_size),
				    catalog_compare_func);
			}
		}
	}

	if (!f) {
		zero(key.language);
		f = bsearch(&key, (const uint8_t *) p + le64toh(h->header_size),
		    le64toh(h->n_items), le64toh(h->catalog_item_size), catalog_compare_func);
	}

	if (!f)
		return NULL;

	return (const char *) p + le64toh(h->header_size) +
	    le64toh(h->n_items) * le64toh(h->catalog_item_size) + le64toh(f->offset);
}

int catalog_get(const char *database, sd_id128_t id, char **_text)
{
	_cleanup_close_ int fd = -1;
	void *p = NULL;
	struct stat st;
	char *text = NULL;
	int r;
	const char *s;

	assert(_text);

	r = open_mmap(database, &fd, &st, &p);
	if (r < 0)
		return r;

	s = find_id(p, id);
	if (!s) {
		r = -ENOENT;
		goto finish;
	}

	text = strdup(s);
	if (!text) {
		r = -ENOMEM;
		goto finish;
	}

	*_text = text;
	r = 0;

finish:
	if (p)
		munmap(p, st.st_size);

	return r;
}

static char *find_header(const char *s, const char *header)
{

	for (;;) {
		const char *v, *e;

		v = startswith(s, header);
		if (v) {
			v += strspn(v, WHITESPACE);
			return strndup(v, strcspn(v, NEWLINE));
		}

		/* End of text */
		e = strchr(s, '\n');
		if (!e)
			return NULL;

		/* End of header */
		if (e == s)
			return NULL;

		s = e + 1;
	}
}

static void dump_catalog_entry(FILE *f, sd_id128_t id, const char *s, bool oneline)
{
	if (oneline) {
		_cleanup_free_ char *subject = NULL, *defined_by = NULL;

		subject = find_header(s, "Subject:");
		defined_by = find_header(s, "Defined-By:");

		fprintf(f, SD_ID128_FORMAT_STR " %s: %s\n", SD_ID128_FORMAT_VAL(id),
		    strna(defined_by), strna(subject));
	} else
		fprintf(f, "-- " SD_ID128_FORMAT_STR "\n%s\n", SD_ID128_FORMAT_VAL(id), s);
}


int catalog_list(FILE *f, const char *database, bool oneline)
{
	_cleanup_close_ int fd = -1;
	void *p = NULL;
	struct stat st;
	const CatalogHeader *h;
	const CatalogItem *items;
	int r;
	unsigned n;
	sd_id128_t last_id;
	bool last_id_set = false;

	r = open_mmap(database, &fd, &st, &p);
	if (r < 0)
		return r;

	h = p;
	items = (const CatalogItem *) ((const uint8_t *) p + le64toh(h->header_size));

	for (n = 0; n < le64toh(h->n_items); n++) {
		const char *s;

		if (last_id_set && sd_id128_equal(last_id, items[n].id))
			continue;

		assert_se(s = find_id(p, items[n].id));

		dump_catalog_entry(f, items[n].id, s, oneline);

		last_id_set = true;
		last_id = items[n].id;
	}

	munmap(p, st.st_size);

	return 0;
}

int catalog_list_items(FILE *f, const char *database, bool oneline, char **items)
{
	char **item;
	int r = 0;

	STRV_FOREACH (item, items) {
		sd_id128_t id;
		int k;
		_cleanup_free_ char *msg = NULL;

		k = sd_id128_from_string(*item, &id);
		if (k < 0) {
			log_error("Failed to parse id128 '%s': %s", *item, strerror(-k));
			if (r == 0)
				r = k;
			continue;
		}

		k = catalog_get(database, id, &msg);
		if (k < 0) {
			log_full(k == -ENOENT ? LOG_NOTICE : LOG_ERR,
			    "Failed to retrieve catalog entry for '%s': %s", *item, strerror(-k));
			if (r == 0)
				r = k;
			continue;
		}

		dump_catalog_entry(f, id, msg, oneline);
	}

	return r;
}
