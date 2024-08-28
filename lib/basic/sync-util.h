/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

int fsync_full(int fd);

int fsync_parent_at(int at_fd, const char *path);

int syncfs_path(int at_fd, const char *path);
