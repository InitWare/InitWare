/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */
/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include <sys/proc.h>
#include <libproc.h>

#include "fdset.h"
#include "util.h"

int
get_parent_of_pid(pid_t pid, pid_t *_ppid)
{
	struct proc_bsdshortinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	*_ppid = info.pbsi_ppid;

	return 0;
}

int
get_process_uid(pid_t pid, uid_t *uid)
{
	struct proc_bsdshortinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	*uid = info.pbsi_uid;

	return 0;
}

int
get_process_gid(pid_t pid, gid_t *gid)
{
	struct proc_bsdshortinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	*gid = info.pbsi_gid;

	return 0;
}

int
get_process_state(pid_t pid)
{
	struct proc_bsdshortinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	if (info.pbsi_status == SZOMB)
		return 'Z';
	else
		return 'O'; // TODO: extend, merge with libkvm procutils
}

int
get_process_comm(pid_t pid, char **name)
{
	struct proc_bsdshortinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	*name = strdup(info.pbsi_comm);

	return 0;
}

int
get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback,
	char **line)
{
	char name[PROC_PIDPATHINFO_SIZE];
	int r;

	r = proc_name(pid, name, PROC_PIDPATHINFO_SIZE);
	if (r < 0) {
		log_error("proc_name failed: %m\n");
		free(name);
		return -errno;
	}

	*line = max_length ? strndup(name, max_length) : strdup(name);
	return r;
}

int
get_process_exe(pid_t pid, char **line)
{
	struct proc_bsdinfo info;
	int r;

	r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info);
	if (r < 0) {
		log_error("proc_pidinfo failed: %m");
		return -errno;
	}

	*line = info.pbi_name[0] ? strdup(info.pbi_name) :
					 strdup(info.pbi_comm);

	return 0;
}
