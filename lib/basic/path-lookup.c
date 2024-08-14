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
#include <unistd.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "install.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "util.h"

int xdg_user_runtime_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;

        assert(ret);
        assert(suffix);

        e = getenv("XDG_RUNTIME_DIR");
        if (!e)
                return -ENXIO;

        j = path_join(e, suffix);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

// int
// user_config_home(char **config_home)
// {
// 	const char *e;
// 	char *r;

// 	e = getenv("XDG_CONFIG_HOME");
// 	if (e) {
// 		r = strappend(e, "/" SVC_PKGDIRNAME "/user");
// 		if (!r)
// 			return -ENOMEM;

// 		*config_home = r;
// 		return 1;
// 	} else {
// 		const char *home;

// 		home = getenv("HOME");
// 		if (home) {
// 			r = strappend(home, "/.config/" SVC_PKGDIRNAME "/user");
// 			if (!r)
// 				return -ENOMEM;

// 			*config_home = r;
// 			return 1;
// 		}
// 	}

// 	return 0;
// }

// int
// user_runtime_dir(char **runtime_dir)
// {
// 	const char *e;
// 	char *r;

// 	e = getenv("XDG_RUNTIME_DIR");
// 	if (e) {
// 		r = strappend(e, "/" SVC_PKGDIRNAME "/user");
// 		if (!r)
// 			return -ENOMEM;

// 		*runtime_dir = r;
// 		return 1;
// 	}

// 	return 0;
// }

// static int
// user_data_home_dir(char **dir, const char *suffix)
// {
// 	const char *e;
// 	char *res;

// 	/* We don't treat /etc/xdg/InitWare here as the spec
//          * suggests because we assume that that is a link to
//          * /etc/InitWare/ anyway. */

// 	e = getenv("XDG_DATA_HOME");
// 	if (e)
// 		res = strappend(e, suffix);
// 	else {
// 		const char *home;

// 		home = getenv("HOME");
// 		if (home)
// 			res = strjoin(home, "/.local/share", suffix, NULL);
// 		else
// 			return 0;
// 	}
// 	if (!res)
// 		return -ENOMEM;

// 	*dir = res;
// 	return 0;
// }

int xdg_user_config_dir(char **ret, const char *suffix) {
        _cleanup_free_ char *j = NULL;
        const char *e;
        int r;

        assert(ret);

        e = getenv("XDG_CONFIG_HOME");
        if (e) {
                j = path_join(e, suffix);
                if (!j)
                        return -ENOMEM;
        } else {
                r = get_home_dir(&j);
                if (r < 0)
                        return r;

                if (!path_extend(&j, "/.config", suffix))
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(j);
        return 0;
}

int xdg_user_data_dir(char **ret, const char *suffix) {
        _cleanup_free_ char *j = NULL;
        const char *e;
        int r;

        assert(ret);
        assert(suffix);

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that is a link to
         * /etc/systemd/ anyway. */

        e = getenv("XDG_DATA_HOME");
        if (e) {
                j = path_join(e, suffix);
                if (!j)
                        return -ENOMEM;
        } else {
                r = get_home_dir(&j);
                if (r < 0)
                        return r;

                if (!path_extend(&j, "/.local/share", suffix))
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(j);
        return 1;
}

int runtime_directory(char **ret, RuntimeScope scope, const char *suffix) {
        int r;

        assert(ret);
        assert(suffix);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));

        /* Accept $RUNTIME_DIRECTORY as authoritative
         * If its missing apply the suffix to /run or $XDG_RUNTIME_DIR
         * if we are in a user runtime scope.
         *
         * Return value indicates whether the suffix was applied or not */

        const char *e = secure_getenv("RUNTIME_DIRECTORY");
        if (e)
                return strdup_to(ret, e);

        if (scope == RUNTIME_SCOPE_USER) {
                r = xdg_user_runtime_dir(ret, suffix);
                if (r < 0)
                        return r;
        } else {
                char *d = path_join("/run", suffix);
                if (!d)
                        return -ENOMEM;
                *ret = d;
        }

        return true;
}

static const char* const user_data_unit_paths[] = {
        "/usr/local/lib/systemd/user",
        "/usr/local/share/systemd/user",
        USER_DATA_UNIT_PATH,
        "/usr/lib/systemd/user",
        "/usr/share/systemd/user",
        NULL
};

static const char* const user_config_unit_paths[] = {
        USER_CONFIG_UNIT_PATH,
        "/etc/systemd/user",
        NULL
};

int xdg_user_dirs(char ***ret_config_dirs, char ***ret_data_dirs) {
        /* Implement the mechanisms defined in
         *
         * https://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */
        const char *e;
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;

        e = getenv("XDG_CONFIG_DIRS");
        if (e)
                config_dirs = strv_split(e, ":");
        else
                config_dirs = strv_new("/etc/xdg");
        if (!config_dirs)
                return -ENOMEM;

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share");
        if (!data_dirs)
                return -ENOMEM;

        *ret_config_dirs = TAKE_PTR(config_dirs);
        *ret_data_dirs = TAKE_PTR(data_dirs);

        return 0;
}

static char** user_dirs(
                const char *persistent_config,
                const char *runtime_config,
                const char *global_persistent_config,
                const char *global_runtime_config,
                const char *generator,
                const char *generator_early,
                const char *generator_late,
                const char *transient,
                const char *persistent_control,
                const char *runtime_control) {

        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
        _cleanup_free_ char *data_home = NULL;
        _cleanup_strv_free_ char **res = NULL;
        int r;

        r = xdg_user_dirs(&config_dirs, &data_dirs);
        if (r < 0)
                return NULL;

        r = xdg_user_data_dir(&data_home, "/systemd/user");
        if (r < 0 && r != -ENXIO)
                return NULL;

        /* Now merge everything we found. */
        if (strv_extend_many(
                            &res,
                            persistent_control,
                            runtime_control,
                            transient,
                            generator_early,
                            persistent_config) < 0)
                return NULL;

        if (strv_extend_strv_concat(&res, (const char* const*) config_dirs, "/systemd/user") < 0)
                return NULL;

        /* global config has lower priority than the user config of the same type */
        if (strv_extend(&res, global_persistent_config) < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) user_config_unit_paths, false) < 0)
                return NULL;

        if (strv_extend_many(
                            &res,
                            runtime_config,
                            global_runtime_config,
                            generator,
                            data_home) < 0)
                return NULL;

        if (strv_extend_strv_concat(&res, (const char* const*) data_dirs, "/systemd/user") < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) user_data_unit_paths, false) < 0)
                return NULL;

        if (strv_extend(&res, generator_late) < 0)
                return NULL;

        if (path_strv_make_absolute_cwd(res) < 0)
                return NULL;

        return TAKE_PTR(res);
}

// HACK: We lose the ability to use non systemd paths?
// static char **
// user_dirs(const char *generator, const char *generator_early,
// 	const char *generator_late)
// {
// 	const char *const config_unit_paths[] = { USER_CONFIG_UNIT_PATH,
// 		SVC_PKGSYSCONFDIR "/user", NULL };

// 	const char *const runtime_unit_path = SVC_PKGRUNSTATEDIR "/user";

// 	const char *const data_unit_paths[] = {
// #ifdef SVC_USE_systemd_paths
// 		"/usr/local/lib/" SVC_PKGDIRNAME "/user",
// 		"/usr/local/share/" SVC_PKGDIRNAME "/user",
// #endif
// 		USER_DATA_UNIT_PATH,
// #ifdef SVC_USE_systemd_paths
// 		"/usr/lib/" SVC_PKGDIRNAME "/user",
// 		"/usr/share/" SVC_PKGDIRNAME "/user",
// #endif
// 		NULL };

// 	const char *e;
// 	_cleanup_free_ char *config_home = NULL, *runtime_dir = NULL,
// 			    *data_home = NULL;
// 	_cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
// 	_cleanup_free_ char **res = NULL;
// 	char **tmp;
// 	int r;

// 	/* Implement the mechanisms defined in
//          *
//          * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
//          *
//          * We look in both the config and the data dirs because we
//          * want to encourage that distributors ship their unit files
//          * as data, and allow overriding as configuration.
//          */

// 	if (user_config_home(&config_home) < 0)
// 		return NULL;

// 	if (user_runtime_dir(&runtime_dir) < 0)
// 		return NULL;

// 	e = getenv("XDG_CONFIG_DIRS");
// 	if (e) {
// 		config_dirs = strv_split(e, ":");
// 		if (!config_dirs)
// 			return NULL;
// 	}

// 	r = user_data_home_dir(&data_home, "/" SVC_PKGDIRNAME "/user");
// 	if (r < 0)
// 		return NULL;

// 	e = getenv("XDG_DATA_DIRS");
// 	if (e)
// 		data_dirs = strv_split(e, ":");
// 	else
// 		data_dirs = strv_new("/usr/local/share", "/usr/share", NULL);
// 	if (!data_dirs)
// 		return NULL;

// 	/* Now merge everything we found. */
// 	if (generator_early)
// 		if (strv_extend(&res, generator_early) < 0)
// 			return NULL;

// 	if (config_home)
// 		if (strv_extend(&res, config_home) < 0)
// 			return NULL;

// 	if (!strv_isempty(config_dirs))
// 		if (strv_extend_strv_concat(&res, config_dirs,
// 			    "/" SVC_PKGDIRNAME "/user") < 0)
// 			return NULL;

// 	if (strv_extend_strv(&res, (char **)config_unit_paths) < 0)
// 		return NULL;

// 	if (runtime_dir)
// 		if (strv_extend(&res, runtime_dir) < 0)
// 			return NULL;

// 	if (strv_extend(&res, runtime_unit_path) < 0)
// 		return NULL;

// 	if (generator)
// 		if (strv_extend(&res, generator) < 0)
// 			return NULL;

// 	if (data_home)
// 		if (strv_extend(&res, data_home) < 0)
// 			return NULL;

// 	if (!strv_isempty(data_dirs))
// 		if (strv_extend_strv_concat(&res, data_dirs, "/" SVC_PKGDIRNAME "/user") <
// 			0)
// 			return NULL;

// 	if (strv_extend_strv(&res, (char **)data_unit_paths) < 0)
// 		return NULL;

// 	if (generator_late)
// 		if (strv_extend(&res, generator_late) < 0)
// 			return NULL;

// 	if (!path_strv_make_absolute_cwd(res))
// 		return NULL;

// 	tmp = res;
// 	res = NULL;
// 	return tmp;
// }

char **
generator_paths(SystemdRunningAs running_as)
{
	if (running_as == SYSTEMD_USER)
		return strv_new(SVC_PKGRUNSTATEDIR "/user-generators",
			SVC_PKGSYSCONFDIR "/user-generators",
			"/usr/local/lib/" SVC_PKGDIRNAME "/user-generators",
			USER_GENERATOR_PATH, NULL);
	else
		return strv_new(SVC_PKGRUNSTATEDIR "/system-generators",
			SVC_PKGSYSCONFDIR "/system-generators",
			"/usr/local/lib/" SVC_PKGDIRNAME "/system-generators",
			SYSTEM_GENERATOR_PATH, NULL);
}

// int
// lookup_paths_init(LookupPaths *p, SystemdRunningAs running_as, bool personal,
// 	const char *root_dir, const char *generator,
// 	const char *generator_early, const char *generator_late)
// {
// 	const char *e;
// 	bool append =
// 		false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */

// 	assert(p);

// 	/* First priority is whatever has been passed to us via env
//          * vars */
// 	e = getenv("SYSTEMD_UNIT_PATH");
// 	if (e) {
// 		if (endswith(e, ":")) {
// 			e = strndupa(e, strlen(e) - 1);
// 			append = true;
// 		}

// 		/* FIXME: empty components in other places should be
//                  * rejected. */

// 		p->unit_path = path_split_and_make_absolute(e);
// 		if (!p->unit_path)
// 			return -ENOMEM;
// 	} else
// 		p->unit_path = NULL;

// 	if (!p->unit_path || append) {
// 		/* Let's figure something out. */

// 		_cleanup_strv_free_ char **unit_path;
// 		int r;

// 		/* For the user units we include share/ in the search
//                  * path in order to comply with the XDG basedir spec.
//                  * For the system stuff we avoid such nonsense. OTOH
//                  * we include /lib in the search path for the system
//                  * stuff but avoid it for user stuff. */

// 		if (running_as == SYSTEMD_USER) {
// 			if (personal)
// 				unit_path = user_dirs(generator,
// 					generator_early, generator_late);
// 			else
// 				unit_path = strv_new(
// 					/* If you modify this you also want to modify
//                                          * systemduserunitpath= in systemd.pc.in, and
//                                          * the arrays in user_dirs() above! */
// 					STRV_IFNOTNULL(generator_early),
// 					USER_CONFIG_UNIT_PATH,
// 					SVC_PKGSYSCONFDIR "/user",
// 					SVC_PKGRUNSTATEDIR "/user",
// 					STRV_IFNOTNULL(generator),
// #ifdef SVC_USE_systemd_paths
// 					"/usr/local/lib/" SVC_PKGDIRNAME "/user",
// 					"/usr/local/share/" SVC_PKGDIRNAME "/user",
// #endif
// 					USER_DATA_UNIT_PATH,
// #ifdef SVC_USE_systemd_paths
// 					"/usr/lib/" SVC_PKGDIRNAME "/user",
// 					"/usr/share/" SVC_PKGDIRNAME "/user",
// #endif
// 					STRV_IFNOTNULL(generator_late), NULL);
// 		} else
// 			unit_path = strv_new(
// 				/* If you modify this you also want to modify
//                                  * systemdsystemunitpath= in systemd.pc.in! */
// 				STRV_IFNOTNULL(generator_early),
// 				SYSTEM_CONFIG_UNIT_PATH, SVC_PKGSYSCONFDIR "/system",
// 				SVC_PKGRUNSTATEDIR "/system",
// 				STRV_IFNOTNULL(generator),
// #ifdef SVC_USE_systemd_paths
// 				"/usr/local/lib/" SVC_PKGDIRNAME "/system",
// #endif
// 				SYSTEM_DATA_UNIT_PATH,
// #ifdef SVC_USE_systemd_paths
// 				"/usr/lib/" SVC_PKGDIRNAME "/system",
// #ifdef HAVE_SPLIT_USR
// 				"/lib/" SVC_PKGDIRNAME "/system",
// #endif
// #endif
// 				STRV_IFNOTNULL(generator_late), NULL);

// 		if (!unit_path)
// 			return -ENOMEM;

// 		r = strv_extend_strv(&p->unit_path, unit_path);
// 		if (r < 0)
// 			return r;
// 	}

// 	if (!path_strv_resolve_uniq(p->unit_path, root_dir))
// 		return -ENOMEM;

// 	if (!strv_isempty(p->unit_path)) {
// 		_cleanup_free_ char *t = strv_join(p->unit_path, "\n\t");
// 		if (!t)
// 			return -ENOMEM;
// 		log_debug(
// 			"Looking for unit files in (higher priority first):\n\t%s",
// 			t);
// 	} else {
// 		log_debug("Ignoring unit files.");
// 		strv_free(p->unit_path);
// 		p->unit_path = NULL;
// 	}

// 	if (running_as == SYSTEMD_SYSTEM) {
// #ifdef HAVE_SYSV_COMPAT
// 		/* /etc/init.d/ compatibility does not matter to users */

// 		e = getenv("SYSTEMD_SYSVINIT_PATH");
// 		if (e) {
// 			p->sysvinit_path = path_split_and_make_absolute(e);
// 			if (!p->sysvinit_path)
// 				return -ENOMEM;
// 		} else
// 			p->sysvinit_path = NULL;

// 		if (strv_isempty(p->sysvinit_path)) {
// 			strv_free(p->sysvinit_path);

// 			p->sysvinit_path = strv_new(
// 				SYSTEM_SYSVINIT_PATH, /* /etc/init.d/ */
// 				NULL);
// 			if (!p->sysvinit_path)
// 				return -ENOMEM;
// 		}

// 		e = getenv("SYSTEMD_SYSVRCND_PATH");
// 		if (e) {
// 			p->sysvrcnd_path = path_split_and_make_absolute(e);
// 			if (!p->sysvrcnd_path)
// 				return -ENOMEM;
// 		} else
// 			p->sysvrcnd_path = NULL;

// 		if (strv_isempty(p->sysvrcnd_path)) {
// 			strv_free(p->sysvrcnd_path);

// 			p->sysvrcnd_path =
// 				strv_new(SYSTEM_SYSVRCND_PATH, /* /etc/rcN.d/ */
// 					NULL);
// 			if (!p->sysvrcnd_path)
// 				return -ENOMEM;
// 		}

// 		if (!path_strv_resolve_uniq(p->sysvinit_path, root_dir))
// 			return -ENOMEM;

// 		if (!path_strv_resolve_uniq(p->sysvrcnd_path, root_dir))
// 			return -ENOMEM;

// 		if (!strv_isempty(p->sysvinit_path)) {
// 			_cleanup_free_ char *t =
// 				strv_join(p->sysvinit_path, "\n\t");
// 			if (!t)
// 				return -ENOMEM;
// 			log_debug("Looking for SysV init scripts in:\n\t%s", t);
// 		} else {
// 			log_debug("Ignoring SysV init scripts.");
// 			strv_free(p->sysvinit_path);
// 			p->sysvinit_path = NULL;
// 		}

// 		if (!strv_isempty(p->sysvrcnd_path)) {
// 			_cleanup_free_ char *t =
// 				strv_join(p->sysvrcnd_path, "\n\t");
// 			if (!t)
// 				return -ENOMEM;

// 			log_debug("Looking for SysV rcN.d links in:\n\t%s", t);
// 		} else {
// 			log_debug("Ignoring SysV rcN.d links.");
// 			strv_free(p->sysvrcnd_path);
// 			p->sysvrcnd_path = NULL;
// 		}
// #else
// 		log_debug("SysV init scripts and rcN.d links support disabled");
// #endif
// 	}

// 	return 0;
// }

static int acquire_generator_dirs(
                RuntimeScope scope,
                const char *tempdir,
                char **generator,
                char **generator_early,
                char **generator_late) {

        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *p = NULL;
        const char *prefix;

        assert(generator);
        assert(generator_early);
        assert(generator_late);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));

        if (scope == RUNTIME_SCOPE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                prefix = tempdir;
        else if (scope == RUNTIME_SCOPE_SYSTEM)
                prefix = "/run/systemd";
        else {
                /* RUNTIME_SCOPE_USER */
                const char *e;

                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return -ENXIO;

                p = path_join(e, "/systemd");
                if (!p)
                        return -ENOMEM;

                prefix = p;
        }

        x = path_join(prefix, "generator");
        if (!x)
                return -ENOMEM;

        y = path_join(prefix, "generator.early");
        if (!y)
                return -ENOMEM;

        z = path_join(prefix, "generator.late");
        if (!z)
                return -ENOMEM;

        *generator = TAKE_PTR(x);
        *generator_early = TAKE_PTR(y);
        *generator_late = TAKE_PTR(z);

        return 0;
}

static int acquire_transient_dir(
                RuntimeScope scope,
                const char *tempdir,
                char **ret) {

        char *transient;

        assert(ret);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));

        if (scope == RUNTIME_SCOPE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                transient = path_join(tempdir, "transient");
        else if (scope == RUNTIME_SCOPE_SYSTEM)
                transient = strdup("/run/systemd/transient");
        else
                return xdg_user_runtime_dir(ret, "/systemd/transient");

        if (!transient)
                return -ENOMEM;
        *ret = transient;
        return 0;
}

static int acquire_config_dirs(RuntimeScope scope, char **persistent, char **runtime) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        assert(persistent);
        assert(runtime);

        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM:
                a = strdup(SYSTEM_CONFIG_UNIT_PATH);
                b = strdup("/run/systemd/system");
                break;

        case RUNTIME_SCOPE_GLOBAL:
                a = strdup(USER_CONFIG_UNIT_PATH);
                b = strdup("/run/systemd/user");
                break;

        case RUNTIME_SCOPE_USER:
                r = xdg_user_config_dir(&a, "/systemd/user");
                if (r < 0 && r != -ENXIO)
                        return r;

                r = xdg_user_runtime_dir(runtime, "/systemd/user");
                if (r < 0) {
                        if (r != -ENXIO)
                                return r;

                        /* If XDG_RUNTIME_DIR is not set, don't consider that fatal, simply initialize the runtime
                         * directory to NULL */
                        *runtime = NULL;
                }

                *persistent = TAKE_PTR(a);

                return 0;

        default:
                assert_not_reached();
        }

        if (!a || !b)
                return -ENOMEM;

        *persistent = TAKE_PTR(a);
        *runtime = TAKE_PTR(b);

        return 0;
}

static int acquire_control_dirs(RuntimeScope scope, char **persistent, char **runtime) {
        _cleanup_free_ char *a = NULL;
        int r;

        assert(persistent);
        assert(runtime);

        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM:  {
                _cleanup_free_ char *b = NULL;

                a = strdup("/etc/systemd/system.control");
                if (!a)
                        return -ENOMEM;

                b = strdup("/run/systemd/system.control");
                if (!b)
                        return -ENOMEM;

                *runtime = TAKE_PTR(b);

                break;
        }

        case RUNTIME_SCOPE_USER:
                r = xdg_user_config_dir(&a, "/systemd/user.control");
                if (r < 0 && r != -ENXIO)
                        return r;

                r = xdg_user_runtime_dir(runtime, "/systemd/user.control");
                if (r < 0) {
                        if (r != -ENXIO)
                                return r;

                        /* If XDG_RUNTIME_DIR is not set, don't consider this fatal, simply initialize the directory to
                         * NULL */
                        *runtime = NULL;
                }

                break;

        case RUNTIME_SCOPE_GLOBAL:
                return -EOPNOTSUPP;

        default:
                assert_not_reached();
        }

        *persistent = TAKE_PTR(a);

        return 0;
}

static int acquire_attached_dirs(
                RuntimeScope scope,
                char **ret_persistent,
                char **ret_runtime) {

        _cleanup_free_ char *a = NULL, *b = NULL;

        assert(ret_persistent);
        assert(ret_runtime);

        /* Portable services are not available to regular users for now. */
        if (scope != RUNTIME_SCOPE_SYSTEM)
                return -EOPNOTSUPP;

        a = strdup("/etc/systemd/system.attached");
        if (!a)
                return -ENOMEM;

        b = strdup("/run/systemd/system.attached");
        if (!b)
                return -ENOMEM;

        *ret_persistent = TAKE_PTR(a);
        *ret_runtime = TAKE_PTR(b);

        return 0;
}

static int patch_root_prefix(char **p, const char *root_dir) {
        char *c;

        assert(p);

        if (!*p)
                return 0;

        c = path_join(root_dir, *p);
        if (!c)
                return -ENOMEM;

        free_and_replace(*p, c);
        return 0;
}

static int patch_root_prefix_strv(char **l, const char *root_dir) {
        int r;

        if (!root_dir)
                return 0;

        STRV_FOREACH(i, l) {
                r = patch_root_prefix(i, root_dir);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int get_paths_from_environ(const char *var, char ***paths, bool *append) {
        const char *e;
        int r;

        assert(var);
        assert(paths);
        assert(append);

        *append = false;

        e = getenv(var);
        if (e) {
                const char *k;

                k = endswith(e, ":");
                if (k) {
                        e = strndupa_safe(e, k - e);
                        *append = true;
                }

                /* FIXME: empty components in other places should be rejected. */

                r = path_split_and_make_absolute(e, paths);
                if (r < 0)
                        return r;
        }

        return 0;
}

// NOTE: We should respect SVC_USE_systemd_paths here!
int lookup_paths_init(
                LookupPaths *lp,
                RuntimeScope scope,
                LookupPathsFlags flags,
                const char *root_dir) {

        _cleanup_(rmdir_and_freep) char *tempdir = NULL;
        _cleanup_free_ char
                *root = NULL,
                *persistent_config = NULL, *runtime_config = NULL,
                *global_persistent_config = NULL, *global_runtime_config = NULL,
                *generator = NULL, *generator_early = NULL, *generator_late = NULL,
                *transient = NULL,
                *persistent_control = NULL, *runtime_control = NULL,
                *persistent_attached = NULL, *runtime_attached = NULL;
        bool append = false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        assert(lp);
        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        if (!empty_or_root(root_dir)) {
                if (scope == RUNTIME_SCOPE_USER)
                        return -EINVAL;

                r = is_dir(root_dir, true);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTDIR;

                root = strdup(root_dir);
                if (!root)
                        return -ENOMEM;
        }

        if (flags & LOOKUP_PATHS_TEMPORARY_GENERATED) {
                r = mkdtemp_malloc("/tmp/systemd-temporary-XXXXXX", &tempdir);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create temporary directory: %m");
        }

        /* Note: when XDG_RUNTIME_DIR is not set this will not return -ENXIO, but simply set runtime_config to NULL */
        r = acquire_config_dirs(scope, &persistent_config, &runtime_config);
        if (r < 0)
                return r;

        if (scope == RUNTIME_SCOPE_USER) {
                r = acquire_config_dirs(RUNTIME_SCOPE_GLOBAL, &global_persistent_config, &global_runtime_config);
                if (r < 0)
                        return r;
        }

        if ((flags & LOOKUP_PATHS_EXCLUDE_GENERATED) == 0) {
                /* Note: if XDG_RUNTIME_DIR is not set, this will fail completely with ENXIO */
                r = acquire_generator_dirs(scope, tempdir,
                                           &generator, &generator_early, &generator_late);
                if (r < 0 && !IN_SET(r, -EOPNOTSUPP, -ENXIO))
                        return r;
        }

        /* Note: if XDG_RUNTIME_DIR is not set, this will fail completely with ENXIO */
        r = acquire_transient_dir(scope, tempdir, &transient);
        if (r < 0 && !IN_SET(r, -EOPNOTSUPP, -ENXIO))
                return r;

        /* Note: when XDG_RUNTIME_DIR is not set this will not return -ENXIO, but simply set runtime_control to NULL */
        r = acquire_control_dirs(scope, &persistent_control, &runtime_control);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        r = acquire_attached_dirs(scope, &persistent_attached, &runtime_attached);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        /* First priority is whatever has been passed to us via env vars */
        r = get_paths_from_environ("SYSTEMD_UNIT_PATH", &paths, &append);
        if (r < 0)
                return r;

        if (!paths || append) {
                /* Let's figure something out. */

                _cleanup_strv_free_ char **add = NULL;

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir spec.
                 * For the system stuff we avoid such nonsense. OTOH
                 * we include /lib in the search path for the system
                 * stuff but avoid it for user stuff. */

                switch (scope) {

                case RUNTIME_SCOPE_SYSTEM:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemdsystemunitpath= in systemd.pc.in! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        SYSTEM_CONFIG_UNIT_PATH,
                                        "/etc/systemd/system",
                                        STRV_IFNOTNULL(persistent_attached),
                                        runtime_config,
                                        "/run/systemd/system",
                                        STRV_IFNOTNULL(runtime_attached),
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/system",
                                        SYSTEM_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/system",
                                        /* To be used ONLY for images which might be legacy split-usr */
                                        STRV_IFNOTNULL(flags & LOOKUP_PATHS_SPLIT_USR ? "/lib/systemd/system" : NULL),
                                        STRV_IFNOTNULL(generator_late));
                        break;

                case RUNTIME_SCOPE_GLOBAL:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemduserunitpath= in systemd.pc.in, and
                                         * the arrays in user_dirs() above! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        USER_CONFIG_UNIT_PATH,
                                        "/etc/systemd/user",
                                        runtime_config,
                                        "/run/systemd/user",
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/share/systemd/user",
                                        "/usr/share/systemd/user",
                                        "/usr/local/lib/systemd/user",
                                        USER_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/user",
                                        STRV_IFNOTNULL(generator_late));
                        break;

                case RUNTIME_SCOPE_USER:
                        add = user_dirs(persistent_config, runtime_config,
                                        global_persistent_config, global_runtime_config,
                                        generator, generator_early, generator_late,
                                        transient,
                                        persistent_control, runtime_control);
                        break;

                default:
                        assert_not_reached();
                }

                if (!add)
                        return -ENOMEM;

                if (paths) {
                        r = strv_extend_strv(&paths, add, true);
                        if (r < 0)
                                return r;
                } else
                        /* Small optimization: if paths is NULL (and it usually is), we can simply assign 'add' to it,
                         * and don't have to copy anything */
                        paths = TAKE_PTR(add);
        }

        r = patch_root_prefix(&persistent_config, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&runtime_config, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&generator, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_early, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_late, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&transient, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&persistent_control, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&runtime_control, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&persistent_attached, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&runtime_attached, root);
        if (r < 0)
                return r;

        r = patch_root_prefix_strv(paths, root);
        if (r < 0)
                return -ENOMEM;

        *lp = (LookupPaths) {
                .search_path = strv_uniq(TAKE_PTR(paths)),

                .persistent_config = TAKE_PTR(persistent_config),
                .runtime_config = TAKE_PTR(runtime_config),

                .generator = TAKE_PTR(generator),
                .generator_early = TAKE_PTR(generator_early),
                .generator_late = TAKE_PTR(generator_late),

                .transient = TAKE_PTR(transient),

                .persistent_control = TAKE_PTR(persistent_control),
                .runtime_control = TAKE_PTR(runtime_control),

                .persistent_attached = TAKE_PTR(persistent_attached),
                .runtime_attached = TAKE_PTR(runtime_attached),

                .root_dir = TAKE_PTR(root),
                .temporary_dir = TAKE_PTR(tempdir),
        };

        return 0;
}

// HACK: We lose SYSV compat?
// void
// lookup_paths_free(LookupPaths *p)
// {
// 	assert(p);

// 	strv_free(p->unit_path);
// 	p->unit_path = NULL;

// #ifdef HAVE_SYSV_COMPAT
// 	strv_free(p->sysvinit_path);
// 	strv_free(p->sysvrcnd_path);
// 	p->sysvinit_path = p->sysvrcnd_path = NULL;
// #endif
// }
void lookup_paths_done(LookupPaths *lp) {
        assert(lp);

        lp->search_path = strv_free(lp->search_path);

        lp->persistent_config = mfree(lp->persistent_config);
        lp->runtime_config = mfree(lp->runtime_config);

        lp->persistent_attached = mfree(lp->persistent_attached);
        lp->runtime_attached = mfree(lp->runtime_attached);

        lp->generator = mfree(lp->generator);
        lp->generator_early = mfree(lp->generator_early);
        lp->generator_late = mfree(lp->generator_late);

        lp->transient = mfree(lp->transient);

        lp->persistent_control = mfree(lp->persistent_control);
        lp->runtime_control = mfree(lp->runtime_control);

        lp->root_dir = mfree(lp->root_dir);
        lp->temporary_dir = mfree(lp->temporary_dir);
}
