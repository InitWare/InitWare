/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "chase.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "def.h"
#include "escape.h"
#include "exit-status.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "sd-messages.h"
#include "set.h"
#include "strv.h"
#include "utf8.h"
#include "util.h"

#ifdef SVC_HAVE_netinet_ether_h
#include <netinet/ether.h>
#endif

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(config_file_hash_ops_fclose,
                                              char, path_hash_func, path_compare,
                                              FILE, safe_fclose);

int
config_item_table_lookup(const void *table, const char *section,
	const char *lvalue, ConfigParserCallback *func, int *ltype, void **data,
	void *userdata)
{
	const ConfigTableItem *t;

	assert(table);
	assert(lvalue);
	assert(func);
	assert(ltype);
	assert(data);

	for (t = table; t->lvalue; t++) {
		if (!streq(lvalue, t->lvalue))
			continue;

		if (!streq_ptr(section, t->section))
			continue;

		*func = t->parse;
		*ltype = t->ltype;
		*data = t->data;
		return 1;
	}

	return 0;
}

int
config_item_perf_lookup(const void *table, const char *section,
	const char *lvalue, ConfigParserCallback *func, int *ltype, void **data,
	void *userdata)
{
	ConfigPerfItemLookup lookup = (ConfigPerfItemLookup)table;
	const ConfigPerfItem *p;

	assert(table);
	assert(lvalue);
	assert(func);
	assert(ltype);
	assert(data);

	if (!section)
		p = lookup(lvalue, strlen(lvalue));
	else {
		char *key;

		key = strjoin(section, ".", lvalue, NULL);
		if (!key)
			return -ENOMEM;

		p = lookup(key, strlen(key));
		free(key);
	}

	if (!p)
		return 0;

	*func = p->parse;
	*ltype = p->ltype;
	*data = (uint8_t *)userdata + p->offset;
	return 1;
}

/* Run the user supplied parser for an assignment */
static int next_assignment(
                const char *unit,
                const char *filename,
                unsigned line,
                ConfigItemLookup lookup,
                const void *table,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                ConfigParseFlags flags,
                void *userdata) {

        ConfigParserCallback func = NULL;
        int ltype = 0;
        void *data = NULL;
        int r;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(lvalue);
        assert(rvalue);

        r = lookup(table, section, lvalue, &func, &ltype, &data, userdata);
        if (r < 0)
                return r;
        if (r > 0) {
                if (!func)
                        return 0;

                return func(unit, filename, line, section, section_line,
                            lvalue, ltype, rvalue, data, userdata);
        }

        /* Warn about unknown non-extension fields. */
        if (!(flags & CONFIG_PARSE_RELAXED) && !startswith(lvalue, "X-"))
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unknown key '%s'%s%s%s, ignoring.",
                           lvalue,
                           section ? " in section [" : "",
                           strempty(section),
                           section ? "]" : "");

        return 0;
}

/* Parse a single logical line */
static int parse_line(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                char **section,
                unsigned *section_line,
                bool *section_ignored,
                char *l, /* is modified */
                void *userdata) {

        char *e;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(l);

        l = strstrip(l);
        if (isempty(l))
                return 0;

        if (l[0] == '\n')
                return 0;

        if (!utf8_is_valid(l))
                return log_syntax_invalid_utf8(unit, LOG_WARNING, filename, line, l);

        if (l[0] == '[') {
                _cleanup_free_ char *n = NULL;
                size_t k;

                k = strlen(l);
                assert(k > 0);

                if (l[k-1] != ']')
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EBADMSG), "Invalid section header '%s'", l);

                n = strndup(l+1, k-2);
                if (!n)
                        return log_oom();

                if (!string_is_safe(n))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EBADMSG), "Bad characters in section header '%s'", l);

                if (sections && !nulstr_contains(sections, n)) {
                        bool ignore;

                        ignore = (flags & CONFIG_PARSE_RELAXED) || startswith(n, "X-");

                        if (!ignore)
                                NULSTR_FOREACH(t, sections)
                                        if (streq_ptr(n, startswith(t, "-"))) { /* Ignore sections prefixed with "-" in valid section list */
                                                ignore = true;
                                                break;
                                        }

                        if (!ignore)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown section '%s'. Ignoring.", n);

                        *section = mfree(*section);
                        *section_line = 0;
                        *section_ignored = true;
                } else {
                        free_and_replace(*section, n);
                        *section_line = line;
                        *section_ignored = false;
                }

                return 0;
        }

        if (sections && !*section) {
                if (!(flags & CONFIG_PARSE_RELAXED) && !*section_ignored)
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Assignment outside of section. Ignoring.");

                return 0;
        }

        e = strchr(l, '=');
        if (!e)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing '=', ignoring line.");
        if (e == l)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing key name before '=', ignoring line.");

        *e = 0;
        e++;

        return next_assignment(unit,
                               filename,
                               line,
                               lookup,
                               table,
                               *section,
                               *section_line,
                               strstrip(l),
                               strstrip(e),
                               flags,
                               userdata);
}

/* Go through the file and parse each line */
int config_parse(
                const char *unit,
                const char *filename,
                FILE *f,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                struct stat *ret_stat) {

        _cleanup_free_ char *section = NULL, *continuation = NULL;
        _cleanup_fclose_ FILE *ours = NULL;
        unsigned line = 0, section_line = 0;
        bool section_ignored = false, bom_seen = false;
        struct stat st;
        int r, fd;

        assert(filename);
        assert(lookup);

        if (!f) {
                f = ours = fopen(filename, "re");
                if (!f) {
                        /* Only log on request, except for ENOENT,
                         * since we return 0 to the caller. */
                        if ((flags & CONFIG_PARSE_WARN) || errno == ENOENT)
                                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                               "Failed to open configuration file '%s': %m", filename);

                        if (errno == ENOENT) {
                                if (ret_stat)
                                        *ret_stat = (struct stat) {};

                                return 0;
                        }

                        return -errno;
                }
        }

        fd = fileno(f);
        if (fd >= 0) { /* stream might not have an fd, let's be careful hence */

                if (fstat(fd, &st) < 0)
                        return log_full_errno(FLAGS_SET(flags, CONFIG_PARSE_WARN) ? LOG_ERR : LOG_DEBUG, errno,
                                              "Failed to fstat(%s): %m", filename);

                (void) stat_warn_permissions(filename, &st);
        } else
                st = (struct stat) {};

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                bool escaped = false;
                char *l, *p, *e;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_error_errno(r, "%s:%u: Line too long", filename, line);

                        return r;
                }
                if (r < 0) {
                        if (FLAGS_SET(flags, CONFIG_PARSE_WARN))
                                log_error_errno(r, "%s:%u: Error while reading configuration file: %m", filename, line);

                        return r;
                }

                line++;

                l = skip_leading_chars(buf, WHITESPACE);
                if (*l != '\0' && strchr(COMMENTS, *l))
                        continue;

                l = buf;
                if (!bom_seen) {
                        char *q;

                        q = startswith(buf, UTF8_BYTE_ORDER_MARK);
                        if (q) {
                                l = q;
                                bom_seen = true;
                        }
                }

                if (continuation) {
                        if (strlen(continuation) + strlen(l) > LONG_LINE_MAX) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_error("%s:%u: Continuation line too long", filename, line);
                                return -ENOBUFS;
                        }

                        if (!strextend(&continuation, l)) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_oom();
                                return -ENOMEM;
                        }

                        p = continuation;
                } else
                        p = l;

                for (e = p; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                }

                if (escaped) {
                        *(e-1) = ' ';

                        if (!continuation) {
                                continuation = strdup(l);
                                if (!continuation) {
                                        if (flags & CONFIG_PARSE_WARN)
                                                log_oom();
                                        return -ENOMEM;
                                }
                        }

                        continue;
                }

                r = parse_line(unit,
                               filename,
                               line,
                               sections,
                               lookup,
                               table,
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               p,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }

                continuation = mfree(continuation);
        }

        if (continuation) {
                r = parse_line(unit,
                               filename,
                               ++line,
                               sections,
                               lookup,
                               table,
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               continuation,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }
        }

        if (ret_stat)
                *ret_stat = st;

        return 1;
}

int hashmap_put_stats_by_path(Hashmap **stats_by_path, const char *path, const struct stat *st) {
        _cleanup_free_ struct stat *st_copy = NULL;
        _cleanup_free_ char *path_copy = NULL;
        int r;

        assert(stats_by_path);
        assert(path);
        assert(st);

        r = hashmap_ensure_allocated(stats_by_path, &path_hash_ops_free_free);
        if (r < 0)
                return r;

        st_copy = newdup(struct stat, st, 1);
        if (!st_copy)
                return -ENOMEM;

        path_copy = strdup(path);
        if (!path_copy)
                return -ENOMEM;

        r = hashmap_put(*stats_by_path, path_copy, st_copy);
        if (r < 0)
                return r;

        assert(r > 0);
        TAKE_PTR(path_copy);
        TAKE_PTR(st_copy);
        return 0;
}

static int config_parse_many_files(
                const char *root,
                const char* const* conf_files,
                char **files,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path) {

        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *dropins = NULL;
        _cleanup_set_free_ Set *inodes = NULL;
        struct stat st;
        int r;

        if (ret_stats_by_path) {
                stats_by_path = hashmap_new(&path_hash_ops_free_free);
                if (!stats_by_path)
                        return -ENOMEM;
        }

        STRV_FOREACH(fn, files) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *fname = NULL;

                r = chase_and_fopen_unlocked(*fn, root, CHASE_AT_RESOLVE_IN_ROOT, "re", &fname, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                int fd = fileno(f);

                r = ordered_hashmap_ensure_put(&dropins, &config_file_hash_ops_fclose, *fn, f);
                if (r < 0) {
                        assert(r != -EEXIST);
                        return r;
                }
                assert(r > 0);
                TAKE_PTR(f);

                /* Get inodes for all drop-ins. Later we'll verify if main config is a symlink to or is
                 * symlinked as one of them. If so, we skip reading main config file directly. */

                _cleanup_free_ struct stat *st_dropin = new(struct stat, 1);
                if (!st_dropin)
                        return -ENOMEM;

                if (fstat(fd, st_dropin) < 0)
                        return -errno;

                r = set_ensure_consume(&inodes, &inode_hash_ops, TAKE_PTR(st_dropin));
                if (r < 0)
                        return r;
        }

        /* First read the first found main config file. */
        STRV_FOREACH(fn, conf_files) {
                _cleanup_fclose_ FILE *f = NULL;

                r = chase_and_fopen_unlocked(*fn, root, CHASE_AT_RESOLVE_IN_ROOT, "re", NULL, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                if (inodes) {
                        if (fstat(fileno(f), &st) < 0)
                                return -errno;

                        if (set_contains(inodes, &st)) {
                                log_debug("%s: symlink to/symlinked as drop-in, will be read later.", *fn);
                                break;
                        }
                }

                r = config_parse(/* unit= */ NULL, *fn, f, sections, lookup, table, flags, userdata, &st);
                if (r < 0)
                        return r;
                assert(r > 0);

                if (ret_stats_by_path) {
                        r = hashmap_put_stats_by_path(&stats_by_path, *fn, &st);
                        if (r < 0)
                                return r;
                }

                break;
        }

        /* Then read all the drop-ins. */

        const char *path_dropin;
        FILE *f_dropin;
        ORDERED_HASHMAP_FOREACH_KEY(f_dropin, path_dropin, dropins) {
                r = config_parse(/* unit= */ NULL, path_dropin, f_dropin, sections, lookup, table, flags, userdata, &st);
                if (r < 0)
                        return r;
                assert(r > 0);

                if (ret_stats_by_path) {
                        r = hashmap_put_stats_by_path(&stats_by_path, path_dropin, &st);
                        if (r < 0)
                                return r;
                }
        }

        if (ret_stats_by_path)
                *ret_stats_by_path = TAKE_PTR(stats_by_path);

        return 0;
}

/* Parse each config file in the directories specified as strv. */
int config_parse_many(
                const char* const* conf_files,
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *root,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,
                char ***ret_dropin_files) {

        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(conf_file_dirs);
        assert(dropin_dirname);
        assert(table);

        r = conf_files_list_dropins(&files, dropin_dirname, root, conf_file_dirs);
        if (r < 0)
                return r;

        r = config_parse_many_files(root, conf_files, files, sections, lookup, table, flags, userdata, ret_stats_by_path);
        if (r < 0)
                return r;

        if (ret_dropin_files)
                *ret_dropin_files = TAKE_PTR(files);

        return 0;
}

int config_parse_standard_file_with_dropins_full(
                const char *root,
                const char *main_file,    /* A path like "systemd/frobnicator.conf" */
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,
                char ***ret_dropin_files) {

        const char* const *conf_paths = (const char* const*) CONF_PATHS_STRV("");
        _cleanup_strv_free_ char **configs = NULL;
        int r;

        /* Build the list of main config files */
        r = strv_extend_strv_biconcat(&configs, root, conf_paths, main_file);
        if (r < 0) {
                if (flags & CONFIG_PARSE_WARN)
                        log_oom();
                return r;
        }

        _cleanup_free_ char *dropin_dirname = strjoin(main_file, ".d");
        if (!dropin_dirname) {
                if (flags & CONFIG_PARSE_WARN)
                        log_oom();
                return -ENOMEM;
        }

        return config_parse_many(
                        (const char* const*) configs,
                        conf_paths,
                        dropin_dirname,
                        root,
                        sections,
                        lookup,
                        table,
                        flags,
                        userdata,
                        ret_stats_by_path,
                        ret_dropin_files);
}

#define DEFINE_PARSER(type, vartype, conv_func)                                \
	int config_parse_##type(const char *unit, const char *filename,        \
		unsigned line, const char *section, unsigned section_line,     \
		const char *lvalue, int ltype, const char *rvalue, void *data, \
		void *userdata)                                                \
	{                                                                      \
		vartype *i = data;                                             \
		int r;                                                         \
                                                                               \
		assert(filename);                                              \
		assert(lvalue);                                                \
		assert(rvalue);                                                \
		assert(data);                                                  \
                                                                               \
		r = conv_func(rvalue, i);                                      \
		if (r < 0)                                                     \
			log_syntax(unit, LOG_ERR, filename, line, -r,          \
				"Failed to parse %s value, ignoring: %s",      \
				#vartype, rvalue);                             \
                                                                               \
		return 0;                                                      \
	}

DEFINE_PARSER(int, int, safe_atoi)
DEFINE_PARSER(long, long, safe_atoli)
DEFINE_PARSER(uint64, uint64_t, safe_atou64)
DEFINE_PARSER(unsigned, unsigned, safe_atou)
DEFINE_PARSER(double, double, safe_atod)
DEFINE_PARSER(nsec, nsec_t, parse_nsec)
DEFINE_PARSER(sec, usec_t, parse_sec)

int
config_parse_iec_size(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	size_t *sz = data;
	off_t o;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	r = parse_size(rvalue, 1024, &o);
	if (r < 0 || (off_t)(size_t)o != o) {
		log_syntax(unit, LOG_ERR, filename, line, r < 0 ? -r : ERANGE,
			"Failed to parse size value, ignoring: %s", rvalue);
		return 0;
	}

	*sz = (size_t)o;
	return 0;
}

int
config_parse_si_size(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	size_t *sz = data;
	off_t o;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	r = parse_size(rvalue, 1000, &o);
	if (r < 0 || (off_t)(size_t)o != o) {
		log_syntax(unit, LOG_ERR, filename, line, r < 0 ? -r : ERANGE,
			"Failed to parse size value, ignoring: %s", rvalue);
		return 0;
	}

	*sz = (size_t)o;
	return 0;
}

int
config_parse_iec_off(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	off_t *bytes = data;
	int r;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	assert_cc(sizeof(off_t) == sizeof(uint64_t));

	r = parse_size(rvalue, 1024, bytes);
	if (r < 0)
		log_syntax(unit, LOG_ERR, filename, line, -r,
			"Failed to parse size value, ignoring: %s", rvalue);

	return 0;
}

int
config_parse_bool(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	int k;
	bool *b = data;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	k = parse_boolean(rvalue);
	if (k < 0) {
		log_syntax(unit, LOG_ERR, filename, line, -k,
			"Failed to parse boolean value, ignoring: %s", rvalue);
		return 0;
	}

	*b = !!k;
	return 0;
}

int config_parse_tristate(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r, *t = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* A tristate is pretty much a boolean, except that it can also take an empty string,
         * indicating "uninitialized", much like NULL is for a pointer type. */

        if (isempty(rvalue)) {
                *t = -1;
                return 1;
        }

        r = parse_tristate(rvalue, t);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse boolean value for %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        return 1;
}

int config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 1;
        }

        if (FLAGS_SET(ltype, CONFIG_PARSE_STRING_SAFE) && !string_is_safe(rvalue)) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(rvalue);
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified string contains unsafe characters, ignoring: %s", strna(escaped));
                return 0;
        }

        if (FLAGS_SET(ltype, CONFIG_PARSE_STRING_ASCII) && !ascii_is_valid(rvalue)) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(rvalue);
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified string contains invalid ASCII characters, ignoring: %s", strna(escaped));
                return 0;
        }

        r = free_and_strdup_warn(s, empty_to_null(rvalue));
        if (r < 0)
                return r;

        return 1;
}

int config_parse_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *n = NULL;
        bool fatal = ltype;
        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                goto finalize;

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        r = path_simplify_and_warn(n, PATH_CHECK_ABSOLUTE | (fatal ? PATH_CHECK_FATAL : 0), unit, filename, line, lvalue);
        if (r < 0)
                return fatal ? -ENOEXEC : 0;

finalize:
        return free_and_replace(*s, n);
}

int config_parse_strv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        for (const char *p = rvalue;;) {
                char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = strv_consume(sv, word);
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_warn_compat(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Disabled reason = ltype;

        switch (reason) {

        case DISABLED_CONFIGURATION:
                log_syntax(unit, LOG_DEBUG, filename, line, 0,
                           "Support for option %s= has been disabled at compile time and it is ignored", lvalue);
                break;

        case DISABLED_LEGACY:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has been removed and it is ignored", lvalue);
                break;

        case DISABLED_EXPERIMENTAL:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has not yet been enabled and it is ignored", lvalue);
                break;
        }

        return 0;
}

int
config_parse_mode(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	mode_t *m = data;
	long l;
	char *x = NULL;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	errno = 0;
	l = strtol(rvalue, &x, 8);
	if (!x || x == rvalue || *x || errno) {
		log_syntax(unit, LOG_ERR, filename, line, errno,
			"Failed to parse mode value, ignoring: %s", rvalue);
		return 0;
	}

	if (l < 0000 || l > 07777) {
		log_syntax(unit, LOG_ERR, filename, line, ERANGE,
			"Mode value out of range, ignoring: %s", rvalue);
		return 0;
	}

	*m = (mode_t)l;
	return 0;
}

int
config_parse_log_facility(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	int *o = data, x;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	x = log_facility_unshifted_from_string(rvalue);
	if (x < 0) {
		log_syntax(unit, LOG_ERR, filename, line, EINVAL,
			"Failed to parse log facility, ignoring: %s", rvalue);
		return 0;
	}

	*o = (x << 3) | LOG_PRI(*o);

	return 0;
}

int
config_parse_log_level(const char *unit, const char *filename, unsigned line,
	const char *section, unsigned section_line, const char *lvalue,
	int ltype, const char *rvalue, void *data, void *userdata)
{
	int *o = data, x;

	assert(filename);
	assert(lvalue);
	assert(rvalue);
	assert(data);

	x = log_level_from_string(rvalue);
	if (x < 0) {
		log_syntax(unit, LOG_ERR, filename, line, EINVAL,
			"Failed to parse log level, ignoring: %s", rvalue);
		return 0;
	}

	*o = (*o & LOG_FACMASK) | x;
	return 0;
}
