/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "alloc-util.h"
#include "chase.h"
#include "dropin.h"
#include "conf-files.h"
#include "fileio-label.h"
#include "mkdir.h"
#include "path-util.h"
#include "strv.h"
#include "util.h"

int
drop_in_file(const char *dir, const char *unit, unsigned level,
	const char *name, char **_p, char **_q)
{
	_cleanup_free_ char *b = NULL;
	char *p, *q;

	char prefix[DECIMAL_STR_MAX(unsigned)];

	assert(unit);
	assert(name);
	assert(_p);
	assert(_q);

	sprintf(prefix, "%u", level);

	b = xescape(name, "/.");
	if (!b)
		return -ENOMEM;

	if (!filename_is_valid(b))
		return -EINVAL;

	p = strjoin(dir, "/", unit, ".d", NULL);
	if (!p)
		return -ENOMEM;

	q = strjoin(p, "/", prefix, "-", b, ".conf", NULL);
	if (!q) {
		free(p);
		return -ENOMEM;
	}

	*_p = p;
	*_q = q;
	return 0;
}

int
write_drop_in(const char *dir, const char *unit, unsigned level,
	const char *name, const char *data)
{
	_cleanup_free_ char *p = NULL, *q = NULL;
	int r;

	assert(dir);
	assert(unit);
	assert(name);
	assert(data);

	r = drop_in_file(dir, unit, level, name, &p, &q);
	if (r < 0)
		return r;

	mkdir_p(p, 0755);
	return write_string_file_atomic_label(q, data);
}

int
write_drop_in_format(const char *dir, const char *unit, unsigned level,
	const char *name, const char *format, ...)
{
	_cleanup_free_ char *p = NULL;
	va_list ap;
	int r;

	assert(dir);
	assert(unit);
	assert(name);
	assert(format);

	va_start(ap, format);
	r = vasprintf(&p, format, ap);
	va_end(ap);

	if (r < 0)
		return -ENOMEM;

	return write_drop_in(dir, unit, level, name, p);
}

// static int
// iterate_dir(const char *path, UnitDependency dependency,
// 	dependency_consumer_t consumer, void *arg, char ***strv)
// {
// 	_cleanup_closedir_ DIR *d = NULL;
// 	int r;

// 	assert(path);

// 	/* The config directories are special, since the order of the
//          * drop-ins matters */
// 	if (dependency < 0) {
// 		r = strv_extend(strv, path);
// 		if (r < 0)
// 			return log_oom();

// 		return 0;
// 	}

// 	assert(consumer);

// 	d = opendir(path);
// 	if (!d) {
// 		/* Ignore ENOENT, after all most units won't have a drop-in dir.
//                  * Also ignore ENAMETOOLONG, users are not even able to create
//                  * the drop-in dir in such case. This mostly happens for device units with long /sys path.
//                  * */
// 		if (IN_SET(errno, ENOENT, ENAMETOOLONG))
// 			return 0;

// 		log_error_errno(errno, "Failed to open directory %s: %m", path);
// 		return -errno;
// 	}

// 	for (;;) {
// 		struct dirent *de;
// 		_cleanup_free_ char *f = NULL;

// 		errno = 0;
// 		de = readdir(d);
// 		if (!de && errno != 0)
// 			return log_error_errno(errno,
// 				"Failed to read directory %s: %m", path);

// 		if (!de)
// 			break;

// 		if (hidden_file(de->d_name))
// 			continue;

// 		f = strjoin(path, "/", de->d_name, NULL);
// 		if (!f)
// 			return log_oom();

// 		r = consumer(dependency, de->d_name, f, arg);
// 		if (r < 0)
// 			return r;
// 	}

// 	return 0;
// }

// int
// unit_file_process_dir(Set *unit_path_cache, const char *unit_path,
// 	const char *name, const char *suffix, UnitDependency dependency,
// 	dependency_consumer_t consumer, void *arg, char ***strv)
// {
// 	_cleanup_free_ char *path = NULL;

// 	assert(unit_path);
// 	assert(name);
// 	assert(suffix);

// 	path = strjoin(unit_path, "/", name, suffix, NULL);
// 	if (!path)
// 		return log_oom();

// 	if (!unit_path_cache || set_get(unit_path_cache, path))
// 		iterate_dir(path, dependency, consumer, arg, strv);

// 	if (unit_name_is_instance(name)) {
// 		_cleanup_free_ char *template = NULL, *p = NULL;
// 		/* Also try the template dir */

// 		template = unit_name_template(name);
// 		if (!template)
// 			return log_oom();

// 		p = strjoin(unit_path, "/", template, suffix, NULL);
// 		if (!p)
// 			return log_oom();

// 		if (!unit_path_cache || set_get(unit_path_cache, p))
// 			iterate_dir(p, dependency, consumer, arg, strv);
// 	}

// 	return 0;
// }

static int unit_file_add_dir(
                const char *original_root,
                const char *path,
                char ***dirs) {

        _cleanup_free_ char *chased = NULL;
        int r;

        assert(path);

        /* This adds [original_root]/path to dirs, if it exists. */

        r = chase(path, original_root, 0, &chased, NULL);
        if (r == -ENOENT) /* Ignore -ENOENT, after all most units won't have a drop-in dir. */
                return 0;
        if (r == -ENAMETOOLONG) {
                /* Also, ignore -ENAMETOOLONG but log about it. After all, users are not even able to create the
                 * drop-in dir in such case. This mostly happens for device units with an overly long /sys path. */
                log_debug_errno(r, "Path '%s' too long, couldn't canonicalize, ignoring.", path);
                return 0;
        }
        if (r < 0)
                return log_warning_errno(r, "Failed to canonicalize path '%s': %m", path);

        if (strv_consume(dirs, TAKE_PTR(chased)) < 0)
                return log_oom();

        return 0;
}

static int unit_file_find_dirs(
                const char *original_root,
                Set *unit_path_cache,
                const char *unit_path,
                const char *name,
                const char *suffix,
                char ***dirs) {

        _cleanup_free_ char *prefix = NULL, *instance = NULL, *built = NULL;
        bool is_instance, chopped;
        const char *dash;
        UnitType type;
        char *path;
        size_t n;
        int r;

        assert(unit_path);
        assert(name);
        assert(suffix);

        path = strjoina(unit_path, "/", name, suffix);
        if (!unit_path_cache || set_get(unit_path_cache, path)) {
                r = unit_file_add_dir(original_root, path, dirs);
                if (r < 0)
                        return r;
        }

        is_instance = unit_name_is_valid(name, UNIT_NAME_INSTANCE);
        if (is_instance) { /* Also try the template dir */
                _cleanup_free_ char *template = NULL;

                r = unit_name_template(name, &template);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate template from unit name: %m");

                r = unit_file_find_dirs(original_root, unit_path_cache, unit_path, template, suffix, dirs);
                if (r < 0)
                        return r;
        }

        /* Return early for top level drop-ins. */
        if (unit_type_from_string(name) >= 0)
                return 0;

        /* Let's see if there's a "-" prefix for this unit name. If so, let's invoke ourselves for it. This will then
         * recursively do the same for all our prefixes. i.e. this means given "foo-bar-waldo.service" we'll also
         * search "foo-bar-.service" and "foo-.service".
         *
         * Note the order in which we do it: we traverse up adding drop-ins on each step. This means the more specific
         * drop-ins may override the more generic drop-ins, which is the intended behaviour. */

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to derive unit name prefix from unit name: %m");

        chopped = false;
        for (;;) {
                dash = strrchr(prefix, '-');
                if (!dash) /* No dash? if so we are done */
                        return 0;

                n = (size_t) (dash - prefix);
                if (n == 0) /* Leading dash? If so, we are done */
                        return 0;

                if (prefix[n+1] != 0 || chopped) {
                        prefix[n+1] = 0;
                        break;
                }

                /* Trailing dash? If so, chop it off and try again, but not more than once. */
                prefix[n] = 0;
                chopped = true;
        }

        if (!unit_prefix_is_valid(prefix))
                return 0;

        type = unit_name_to_type(name);
        if (type < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to derive unit type from unit name: %s",
                                       name);

        if (is_instance) {
                r = unit_name_to_instance(name, &instance);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive unit name instance from unit name: %m");
        }

        r = unit_name_build_from_type(prefix, instance, type, &built);
        if (r < 0)
                return log_error_errno(r, "Failed to build prefix unit name: %m");

        return unit_file_find_dirs(original_root, unit_path_cache, unit_path, built, suffix, dirs);
}

int unit_file_find_dropin_paths(
                const char *original_root,
                char **lookup_path,
                Set *unit_path_cache,
                const char *dir_suffix,
                const char *file_suffix,
                const char *name,
                const Set *aliases,
                char ***ret) {

        _cleanup_strv_free_ char **dirs = NULL;
        const char *n;
        int r;

        assert(ret);

        if (name)
                STRV_FOREACH(p, lookup_path)
                        (void) unit_file_find_dirs(original_root, unit_path_cache, *p, name, dir_suffix, &dirs);

        SET_FOREACH(n, aliases)
                STRV_FOREACH(p, lookup_path)
                        (void) unit_file_find_dirs(original_root, unit_path_cache, *p, n, dir_suffix, &dirs);

        /* All the names in the unit are of the same type so just grab one. */
        n = name ?: (const char*) set_first(aliases);
        if (n) {
                UnitType type = _UNIT_TYPE_INVALID;

                type = unit_name_to_type(n);
                if (type < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to derive unit type from unit name: %s", n);

                /* Special top level drop in for "<unit type>.<suffix>". Add this last as it's the most generic
                 * and should be able to be overridden by more specific drop-ins. */
                STRV_FOREACH(p, lookup_path)
                        (void) unit_file_find_dirs(original_root,
                                                   unit_path_cache,
                                                   *p,
                                                   unit_type_to_string(type),
                                                   dir_suffix,
                                                   &dirs);
        }

        if (strv_isempty(dirs)) {
                *ret = NULL;
                return 0;
        }

        r = conf_files_list_strv(ret, file_suffix, NULL, 0, (const char**) dirs);
        if (r < 0)
                return log_warning_errno(r, "Failed to create the list of configuration files: %m");

        return 1;
}
