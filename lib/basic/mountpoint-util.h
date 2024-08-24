/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

int name_to_handle_at_loop(int fd, const char *path, struct file_handle **ret_handle, int *ret_mnt_id, int flags);

int path_get_mnt_id_at_fallback(int dir_fd, const char *path, int *ret);

bool path_below_api_vfs(const char *p);
