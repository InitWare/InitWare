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

#ifndef DEF_H_
#define DEF_H_

#include "compat.h"
#include "util.h"

#define DEFAULT_TIMEOUT_USEC (90 * USEC_PER_SEC)
#define DEFAULT_RESTART_USEC (100 * USEC_PER_MSEC)
#define DEFAULT_CONFIRM_USEC (30 * USEC_PER_SEC)

#define DEFAULT_START_LIMIT_INTERVAL (10 * USEC_PER_SEC)
#define DEFAULT_START_LIMIT_BURST 5

#define DEFAULT_EXIT_USEC (5 * USEC_PER_MINUTE)

#define SYSTEMD_CGROUP_CONTROLLER "name=systemd"

#define SIGNALS_CRASH_HANDLER SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGQUIT, SIGABRT
#define SIGNALS_IGNORE SIGPIPE

#define DIGITS "0123456789"
#define LOWERCASE_LETTERS "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS LOWERCASE_LETTERS UPPERCASE_LETTERS

#ifdef HAVE_SPLIT_USR
#define KBD_KEYMAP_DIRS             \
	"/usr/share/keymaps/\0"     \
	"/usr/share/kbd/keymaps/\0" \
	"/usr/lib/kbd/keymaps/\0"   \
	"/lib/kbd/keymaps/\0"
#else
#define KBD_KEYMAP_DIRS             \
	"/usr/share/keymaps/\0"     \
	"/usr/share/kbd/keymaps/\0" \
	"/usr/lib/kbd/keymaps/\0"
#endif

#ifdef Use_SystemdDBus
#define SCHEDULER_DBUS_BUSNAME "org.freedesktop.systemd1"
#define SCHEDULER_DBUS_INTERFACE SCHEDULER_DBUS_BUSNAME
#define SESSIOND_DBUS_BUSNAME "org.freedesktop.login1"
#define SESSIOND_DBUS_INTERFACE SESSIOND_DBUS_BUSNAME
#else
#define SCHEDULER_DBUS_BUSNAME "org.InitWare.Scheduler1"
#define SCHEDULER_DBUS_INTERFACE SCHEDULER_DBUS_BUSNAME
#define SESSIOND_DBUS_BUSNAME "org.InitWare.SessionManager1"
#define SESSIOND_DBUS_INTERFACE SESSIOND_DBUS_BUSNAME
#endif

#define SCHEDULER_DBUS_INTERFACE_MANAGER SCHEDULER_DBUS_INTERFACE ".Manager"

#endif /* DEF_H_ */
