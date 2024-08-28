/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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
#include "import-util.h"
#include "nulstr-util.h"
#include "string-table.h"
#include "util.h"

int
import_url_last_component(const char *url, char **ret)
{
	const char *e, *p;
	char *s;

	e = strchrnul(url, '?');

	while (e > url && e[-1] == '/')
		e--;

	p = e;
	while (p > url && p[-1] != '/')
		p--;

	if (e <= p)
		return -EINVAL;

	s = strndup(p, e - p);
	if (!s)
		return -ENOMEM;

	*ret = s;
	return 0;
}

int
import_url_change_last_component(const char *url, const char *suffix,
	char **ret)
{
	const char *e;
	char *s;

	assert(url);
	assert(ret);

	e = strchrnul(url, '?');

	while (e > url && e[-1] == '/')
		e--;

	while (e > url && e[-1] != '/')
		e--;

	if (e <= url)
		return -EINVAL;

	s = new (char, (e - url) + strlen(suffix) + 1);
	if (!s)
		return -ENOMEM;

	strcpy(mempcpy(s, url, e - url), suffix);
	*ret = s;
	return 0;
}

static const char *const import_verify_table[_IMPORT_VERIFY_MAX] = {
	[IMPORT_VERIFY_NO] = "no",
	[IMPORT_VERIFY_CHECKSUM] = "checksum",
	[IMPORT_VERIFY_SIGNATURE] = "signature",
};

DEFINE_STRING_TABLE_LOOKUP(import_verify, ImportVerify);

int
tar_strip_suffixes(const char *name, char **ret)
{
	const char *e;
	char *s;

	e = endswith(name, ".tar");
	if (!e)
		e = endswith(name, ".tar.xz");
	if (!e)
		e = endswith(name, ".tar.gz");
	if (!e)
		e = endswith(name, ".tar.bz2");
	if (!e)
		e = endswith(name, ".tgz");
	if (!e)
		e = strchr(name, 0);

	if (e <= name)
		return -EINVAL;

	s = strndup(name, e - name);
	if (!s)
		return -ENOMEM;

	*ret = s;
	return 0;
}

int
raw_strip_suffixes(const char *p, char **ret)
{
	static const char suffixes[] = ".xz\0"
				       ".gz\0"
				       ".bz2\0"
				       ".raw\0"
				       ".qcow2\0"
				       ".img\0"
				       ".bin\0";

	_cleanup_free_ char *q = NULL;

	q = strdup(p);
	if (!q)
		return -ENOMEM;

	for (;;) {
		const char *sfx;
		bool changed = false;

		NULSTR_FOREACH (sfx, suffixes) {
			char *e;

			e = endswith(q, sfx);
			if (e) {
				*e = 0;
				changed = true;
			}
		}

		if (!changed)
			break;
	}

	*ret = q;
	q = NULL;

	return 0;
}
