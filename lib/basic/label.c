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

#include "label.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "util.h"

static const LabelOps *label_ops = NULL;

int
label_fix(const char *path, bool ignore_enoent, bool ignore_erofs)
{
	int r, q;

	r = mac_selinux_fix(path, ignore_enoent, ignore_erofs);
	q = mac_smack_fix(path, ignore_enoent, ignore_erofs);

	if (r < 0)
		return r;
	if (q < 0)
		return q;

	return 0;
}

int
mkdir_label(const char *path, mode_t mode)
{
	int r;

	assert(path);

	r = mac_selinux_create_file_prepare(path, S_IFDIR);
	if (r < 0)
		return r;

	if (mkdir(path, mode) < 0)
		r = -errno;

	mac_selinux_create_file_clear();

	if (r < 0)
		return r;

	return mac_smack_fix(path, false, false);
}

int
symlink_label(const char *old_path, const char *new_path)
{
	int r;

	assert(old_path);
	assert(new_path);

	r = mac_selinux_create_file_prepare(new_path, S_IFLNK);
	if (r < 0)
		return r;

	if (symlink(old_path, new_path) < 0)
		r = -errno;

	mac_selinux_create_file_clear();

	if (r < 0)
		return r;

	return mac_smack_fix(new_path, false, false);
}

int label_ops_pre(int dir_fd, const char *path, mode_t mode) {
        if (!label_ops || !label_ops->pre)
                return 0;

        return label_ops->pre(dir_fd, path, mode);
}

int label_ops_post(int dir_fd, const char *path) {
        if (!label_ops || !label_ops->post)
                return 0;

        return label_ops->post(dir_fd, path);
}
