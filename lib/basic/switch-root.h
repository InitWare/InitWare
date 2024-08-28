#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Harald Hoyer, Lennart Poettering

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

typedef enum SwitchRootFlags {
        SWITCH_ROOT_DESTROY_OLD_ROOT      = 1 << 0, /* rm -rf old root when switching – under the condition
                                                     * that it is backed by non-persistent tmpfs/ramfs/… */
        SWITCH_ROOT_DONT_SYNC             = 1 << 1, /* don't call sync() immediately before switching root */
        SWITCH_ROOT_RECURSIVE_RUN         = 1 << 2, /* move /run/ with MS_REC from old to new root */
} SwitchRootFlags;

int switch_root(const char *new_root, const char *old_root_after, SwitchRootFlags flags);
