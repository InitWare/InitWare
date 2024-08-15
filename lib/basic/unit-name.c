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
#include <string.h>

#include "alloc-util.h"
#include "bus-label.h"
#include "def.h"
#include "path-util.h"
#include "string-table.h"
#include "strv.h"
#include "unit-name.h"
#include "util.h"

/* Characters valid in a unit name. */
#define VALID_CHARS                             \
        DIGITS                                  \
        LETTERS                                 \
        ":-_.\\"

/* The same, but also permits the single @ character that may appear */
#define VALID_CHARS_WITH_AT                     \
        "@"                                     \
        VALID_CHARS

/* All chars valid in a unit name glob */
#define VALID_CHARS_GLOB                        \
        VALID_CHARS_WITH_AT                     \
        "[]!-*?"

#define UNIT_NAME_HASH_LENGTH_CHARS 16

static const char *const unit_type_table[_UNIT_TYPE_MAX] = {
	[UNIT_SERVICE] = "service",
	[UNIT_SOCKET] = "socket",
	[UNIT_TARGET] = "target",
	[UNIT_SNAPSHOT] = "snapshot",
	[UNIT_TIMER] = "timer",
	[UNIT_PATH] = "path",
	[UNIT_SLICE] = "slice",
	[UNIT_SCOPE] = "scope"
#ifdef SVC_USE_Device
		[UNIT_DEVICE] = "device",
#endif
#ifdef SVC_USE_Mount
	[UNIT_MOUNT] = "mount",
	[UNIT_AUTOMOUNT] = "automount",
	[UNIT_SWAP] = "swap",
#endif
};

DEFINE_STRING_TABLE_LOOKUP(unit_type, UnitType);

static const char *const unit_load_state_table[_UNIT_LOAD_STATE_MAX] = {
	[UNIT_STUB] = "stub",
	[UNIT_LOADED] = "loaded",
	[UNIT_NOT_FOUND] = "not-found",
	[UNIT_ERROR] = "error",
	[UNIT_MERGED] = "merged",
	[UNIT_MASKED] = "masked"
};

DEFINE_STRING_TABLE_LOOKUP(unit_load_state, UnitLoadState);

bool
unit_name_is_valid(const char *n, UnitNameFlags flags)
{
	const char *e, *i, *at;

	assert((flags &
		       ~(UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE |
			       UNIT_NAME_TEMPLATE)) == 0);

	if (_unlikely_(flags == 0))
		return false;

	if (isempty(n))
		return false;

	if (strlen(n) >= UNIT_NAME_MAX)
		return false;

	e = strrchr(n, '.');
	if (!e || e == n)
		return false;

	if (unit_type_from_string(e + 1) < 0)
		return false;

	for (i = n, at = NULL; i < e; i++) {
		if (*i == '@' && !at)
			at = i;

		if (!strchr("@" VALID_CHARS, *i))
			return false;
	}

	if (at == n)
		return false;

	if (flags & UNIT_NAME_PLAIN)
		if (!at)
			return true;

	if (flags & UNIT_NAME_INSTANCE)
		if (at && e > at + 1)
			return true;

	if (flags & UNIT_NAME_TEMPLATE)
		if (at && e == at + 1)
			return true;

	return false;
}

bool
unit_instance_is_valid(const char *i)
{
	/* The max length depends on the length of the string, so we
         * don't really check this here. */

	if (isempty(i))
		return false;

	/* We allow additional @ in the instance string, we do not
         * allow them in the prefix! */

	return in_charset(i, "@" VALID_CHARS);
}

bool
unit_prefix_is_valid(const char *p)
{
	/* We don't allow additional @ in the instance string */

	if (isempty(p))
		return false;

	return in_charset(p, VALID_CHARS);
}

int
unit_name_to_instance(const char *n, char **instance)
{
	const char *p, *d;
	char *i;

	assert(n);
	assert(instance);

	/* Everything past the first @ and before the last . is the instance */
	p = strchr(n, '@');
	if (!p) {
		*instance = NULL;
		return 0;
	}

	d = strrchr(n, '.');
	if (!d)
		return -EINVAL;
	if (d < p)
		return -EINVAL;

	i = strndup(p + 1, d - p - 1);
	if (!i)
		return -ENOMEM;

	*instance = i;
	return 1;
}

int unit_name_to_prefix_and_instance(const char *n, char **ret) {
        const char *d;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        d = strrchr(n, '.');
        if (!d)
                return -EINVAL;

        s = strndup(n, d - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_to_prefix(const char *n, char **ret) {
        const char *p;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        p = strchr(n, '@');
        if (!p)
                p = strrchr(n, '.');

        assert_se(p);

        s = strndup(n, p - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

char *
unit_name_change_suffix(const char *n, const char *suffix)
{
	char *e, *r;
	size_t a, b;

	assert(n);
	assert(suffix);
	assert(suffix[0] == '.');

	assert_se(e = strrchr(n, '.'));
	a = e - n;
	b = strlen(suffix);

	r = new (char, a + b + 1);
	if (!r)
		return NULL;

	strcpy(mempcpy(r, n, a), suffix);
	return r;
}

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret) {
        UnitType type;

        assert(prefix);
        assert(suffix);
        assert(ret);

        if (suffix[0] != '.')
                return -EINVAL;

        type = unit_type_from_string(suffix + 1);
        if (type < 0)
                return type;

        return unit_name_build_from_type(prefix, instance, type, ret);
}

int unit_name_build_from_type(const char *prefix, const char *instance, UnitType type, char **ret) {
        _cleanup_free_ char *s = NULL;
        const char *ut;

        assert(prefix);
        assert(type >= 0);
        assert(type < _UNIT_TYPE_MAX);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        ut = unit_type_to_string(type);

        if (instance) {
                if (!unit_instance_is_valid(instance))
                        return -EINVAL;

                s = strjoin(prefix, "@", instance, ".", ut);
        } else
                s = strjoin(prefix, ".", ut);
        if (!s)
                return -ENOMEM;

        /* Verify that this didn't grow too large (or otherwise is invalid) */
        if (!unit_name_is_valid(s, instance ? UNIT_NAME_INSTANCE : UNIT_NAME_PLAIN))
                return -EINVAL;

        *ret = TAKE_PTR(s);
        return 0;
}

static char *
do_escape_char(char c, char *t)
{
	assert(t);

	*(t++) = '\\';
	*(t++) = 'x';
	*(t++) = hexchar(c >> 4);
	*(t++) = hexchar(c);

	return t;
}

static char *
do_escape(const char *f, char *t)
{
	assert(f);
	assert(t);

	/* do not create units with a leading '.', like for "/.dotdir" mount points */
	if (*f == '.') {
		t = do_escape_char(*f, t);
		f++;
	}

	for (; *f; f++) {
		if (*f == '/')
			*(t++) = '-';
		else if (*f == '-' || *f == '\\' || !strchr(VALID_CHARS, *f))
			t = do_escape_char(*f, t);
		else
			*(t++) = *f;
	}

	return t;
}

static char *
do_escape_mangle(const char *f, enum unit_name_mangle allow_globs, char *t)
{
	const char *valid_chars;

	assert(f);
	assert(IN_SET(allow_globs, MANGLE_GLOB, MANGLE_NOGLOB));
	assert(t);

	/* We'll only escape the obvious characters here, to play
         * safe. */

	valid_chars = allow_globs == MANGLE_GLOB ? "@" VALID_CHARS "[]!-*?" :
							 "@" VALID_CHARS;

	for (; *f; f++) {
		if (*f == '/')
			*(t++) = '-';
		else if (!strchr(valid_chars, *f))
			t = do_escape_char(*f, t);
		else
			*(t++) = *f;
	}

	return t;
}

char *
unit_name_escape(const char *f)
{
	char *r, *t;

	assert(f);

	r = new (char, strlen(f) * 4 + 1);
	if (!r)
		return NULL;

	t = do_escape(f, r);
	*t = 0;

	return r;
}

int unit_name_unescape(const char *f, char **ret) {
        _cleanup_free_ char *r = NULL;
        char *t;

        assert(f);

        r = strdup(f);
        if (!r)
                return -ENOMEM;

        for (t = r; *f; f++) {
                if (*f == '-')
                        *(t++) = '/';
                else if (*f == '\\') {
                        int a, b;

                        if (f[1] != 'x')
                                return -EINVAL;

                        a = unhexchar(f[2]);
                        if (a < 0)
                                return -EINVAL;

                        b = unhexchar(f[3]);
                        if (b < 0)
                                return -EINVAL;

                        *(t++) = (char) (((uint8_t) a << 4U) | (uint8_t) b);
                        f += 3;
                } else
                        *(t++) = *f;
        }

        *t = 0;

        *ret = TAKE_PTR(r);

        return 0;
}

char *
unit_name_path_escape(const char *f)
{
	_cleanup_free_ char *p = NULL;

	assert(f);

	p = strdup(f);
	if (!p)
		return NULL;

	path_kill_slashes(p);

	if (STR_IN_SET(p, "/", ""))
		return strdup("-");

	return unit_name_escape(p[0] == '/' ? p + 1 : p);
}

int unit_name_path_unescape(const char *f, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(f);

        if (isempty(f))
                return -EINVAL;

        if (streq(f, "-")) {
                s = strdup("/");
                if (!s)
                        return -ENOMEM;
        } else {
                _cleanup_free_ char *w = NULL;

                r = unit_name_unescape(f, &w);
                if (r < 0)
                        return r;

                /* Don't accept trailing or leading slashes */
                if (startswith(w, "/") || endswith(w, "/"))
                        return -EINVAL;

                /* Prefix a slash again */
                s = strjoin("/", w);
                if (!s)
                        return -ENOMEM;

                if (!path_is_normalized(s))
                        return -EINVAL;
        }

        if (ret)
                *ret = TAKE_PTR(s);

        return 0;
}

bool
unit_name_is_template(const char *n)
{
	const char *p, *e;

	assert(n);

	p = strchr(n, '@');
	if (!p)
		return false;

	e = strrchr(p + 1, '.');
	if (!e)
		return false;

	return e == p + 1;
}

bool
unit_name_is_instance(const char *n)
{
	const char *p, *e;

	assert(n);

	p = strchr(n, '@');
	if (!p)
		return false;

	e = strrchr(p + 1, '.');
	if (!e)
		return false;

	return e > p + 1;
}

int unit_name_replace_instance_full(
                const char *original,
                const char *instance,
                bool accept_glob,
                char **ret) {

        _cleanup_free_ char *s = NULL;
        const char *prefix, *suffix;
        size_t pl;

        assert(original);
        assert(instance);
        assert(ret);

        if (!unit_name_is_valid(original, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;
        if (!unit_instance_is_valid(instance) && !(accept_glob && in_charset(instance, VALID_CHARS_GLOB)))
                return -EINVAL;

        prefix = ASSERT_PTR(strchr(original, '@'));
        suffix = ASSERT_PTR(strrchr(original, '.'));
        assert(prefix < suffix);

        pl = prefix - original + 1; /* include '@' */

        s = new(char, pl + strlen(instance) + strlen(suffix) + 1);
        if (!s)
                return -ENOMEM;

// #if HAS_FEATURE_MEMORY_SANITIZER
// HACK: MSAN SUPPORT
#if 0
        /* MSan doesn't like stpncpy... See also https://github.com/google/sanitizers/issues/926 */
        memzero(s, pl + strlen(instance) + strlen(suffix) + 1);
#endif

        strcpy(stpcpy(stpncpy(s, original, pl), instance), suffix);

        /* Make sure the resulting name still is valid, i.e. didn't grow too large. Globs will be expanded
         * by clients when used, so the check is pointless. */
        if (!accept_glob && !unit_name_is_valid(s, UNIT_NAME_INSTANCE))
                return -EINVAL;

        *ret = TAKE_PTR(s);
        return 0;
}

bool unit_name_is_hashed(const char *name) {
        char *s;

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN))
                return false;

        assert_se(s = strrchr(name, '.'));

        if (s - name < UNIT_NAME_HASH_LENGTH_CHARS + 1)
                return false;

        s -= UNIT_NAME_HASH_LENGTH_CHARS;
        if (s[-1] != '_')
                return false;

        for (size_t i = 0; i < UNIT_NAME_HASH_LENGTH_CHARS; i++)
                if (!strchr(LOWERCASE_HEXDIGITS, s[i]))
                        return false;

        return true;
}

int unit_name_template(const char *f, char **ret) {
        const char *p, *e;
        char *s;
        size_t a;

        assert(f);
        assert(ret);

        if (!unit_name_is_valid(f, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;

        assert_se(p = strchr(f, '@'));
        assert_se(e = strrchr(f, '.'));

        a = p - f;

        s = new(char, a + 1 + strlen(e) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, f, a + 1), e);

        *ret = s;
        return 0;
}

char *
unit_name_from_path(const char *path, const char *suffix)
{
	_cleanup_free_ char *p = NULL;

	assert(path);
	assert(suffix);

	p = unit_name_path_escape(path);
	if (!p)
		return NULL;

	return strappend(p, suffix);
}

char *
unit_name_from_path_instance(const char *prefix, const char *path,
	const char *suffix)
{
	_cleanup_free_ char *p = NULL;

	assert(prefix);
	assert(path);
	assert(suffix);

	p = unit_name_path_escape(path);
	if (!p)
		return NULL;

	return strjoin(prefix, "@", p, suffix, NULL);
}

int unit_name_to_path(const char *name, char **ret) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(name);

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return r;

        if (unit_name_is_hashed(name))
                return -ENAMETOOLONG;

        return unit_name_path_unescape(prefix, ret);
}

char *
unit_dbus_path_from_name(const char *name)
{
	_cleanup_free_ char *e = NULL;

	assert(name);

	e = bus_label_escape(name);
	if (!e)
		return NULL;

	return strappend("/org/freedesktop/systemd1/unit/", e);
}

int
unit_name_from_dbus_path(const char *path, char **name)
{
	const char *e;
	char *n;

	e = startswith(path, "/org/freedesktop/systemd1/unit/");
	if (!e)
		return -EINVAL;

	n = bus_label_unescape(e);
	if (!n)
		return -ENOMEM;

	*name = n;
	return 0;
}

/**
 *  Convert a string to a unit name. /dev/blah is converted to dev-blah.device,
 *  /blah/blah is converted to blah-blah.mount, anything else is left alone,
 *  except that @suffix is appended if a valid unit suffix is not present.
 *
 *  If @allow_globs, globs characters are preserved. Otherwise they are escaped.
 */
char *
unit_name_mangle_with_suffix(const char *name,
	enum unit_name_mangle allow_globs, const char *suffix)
{
	char *r, *t;

	assert(name);
	assert(suffix);
	assert(suffix[0] == '.');

	if (is_device_path(name))
		return unit_name_from_path(name, ".device");

	if (path_is_absolute(name))
		return unit_name_from_path(name, ".mount");

	r = new (char, strlen(name) * 4 + strlen(suffix) + 1);
	if (!r)
		return NULL;

	t = do_escape_mangle(name, allow_globs, r);

	if (unit_name_to_type(name) < 0)
		strcpy(t, suffix);
	else
		*t = 0;

	return r;
}

UnitType
unit_name_to_type(const char *n)
{
	const char *e;

	assert(n);

	e = strrchr(n, '.');
	if (!e)
		return _UNIT_TYPE_INVALID;

	return unit_type_from_string(e + 1);
}

int
build_subslice(const char *slice, const char *name, char **subslice)
{
	char *ret;

	assert(slice);
	assert(name);
	assert(subslice);

	if (streq(slice, "-.slice"))
		ret = strappend(name, ".slice");
	else {
		char *e;

		e = endswith(slice, ".slice");
		if (!e)
			return -EINVAL;

		ret = new (char, (e - slice) + 1 + strlen(name) + 6 + 1);
		if (!ret)
			return -ENOMEM;

		stpcpy(stpcpy(stpcpy(mempcpy(ret, slice, e - slice), "-"),
			       name),
			".slice");
	}

	*subslice = ret;
	return 0;
}

static const char *const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
	[UNIT_REQUIRES] = "Requires",
	[UNIT_REQUIRES_OVERRIDABLE] = "RequiresOverridable",
	[UNIT_REQUISITE] = "Requisite",
	[UNIT_REQUISITE_OVERRIDABLE] = "RequisiteOverridable",
	[UNIT_WANTS] = "Wants",
	[UNIT_BINDS_TO] = "BindsTo",
	[UNIT_PART_OF] = "PartOf",
	[UNIT_REQUIRED_BY] = "RequiredBy",
	[UNIT_REQUIRED_BY_OVERRIDABLE] = "RequiredByOverridable",
	[UNIT_WANTED_BY] = "WantedBy",
	[UNIT_BOUND_BY] = "BoundBy",
	[UNIT_CONSISTS_OF] = "ConsistsOf",
	[UNIT_CONFLICTS] = "Conflicts",
	[UNIT_CONFLICTED_BY] = "ConflictedBy",
	[UNIT_BEFORE] = "Before",
	[UNIT_AFTER] = "After",
	[UNIT_ON_FAILURE] = "OnFailure",
	[UNIT_TRIGGERS] = "Triggers",
	[UNIT_TRIGGERED_BY] = "TriggeredBy",
	[UNIT_PROPAGATES_RELOAD_TO] = "PropagatesReloadTo",
	[UNIT_RELOAD_PROPAGATED_FROM] = "ReloadPropagatedFrom",
	[UNIT_JOINS_NAMESPACE_OF] = "JoinsNamespaceOf",
	[UNIT_REFERENCES] = "References",
	[UNIT_REFERENCED_BY] = "ReferencedBy",
};

DEFINE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
