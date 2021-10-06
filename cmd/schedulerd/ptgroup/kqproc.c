/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */

/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include <sys/types.h>
#include <sys/event.h>

#include "kqproc.h"
#include "manager.h"
#include "sd-event.h"

#ifdef SVC_PLAT_MacOS
#include <libproc.h>

#define PROC_FILTER_FLAGS NOTE_EXIT | NOTE_FORK
#else
#define PROC_FILTER_FLAGS NOTE_EXIT | NOTE_TRACK
#define NOTE_EXITSTATUS 0
#endif

static void
dispatch_note_fork(PTManager *ptm, int ppid)
{
#ifdef Sys_Plat_MacOS
	pid_t subprocs[255];
	int subproccnt;

	subproccnt = proc_listchildpids(ppid, subprocs, sizeof subprocs);
	if (subproccnt < 0) {
		log_error("proc_listchildpids failed: %m");
		return;
	}

	for (int i = 0; i < subproccnt; i++) {
		struct kevent kev;
		int r;

		EV_SET(&kev, subprocs[i], EVFILT_PROC, EV_ADD,
			PROC_FILTER_FLAGS, 0, NULL);
		r = kevent(ptm->group.manager->kqproc_io.fd, &kev, 1, NULL, 0,
			NULL);

		// FIXME: By rights, we shouldn't do any I/O in this loop.
		if (r < 0)
			log_error("Failed to watch PID %lld: %m",
				(long long)subprocs[i]);
	}

	/*
	 * Leave actually updating the PTGroups structures until after we've
	 * hopefully attached the PROC filter to all children in the prior loop.
	 * This helps our odds in this race.
	 */
	for (int i = 0; i < subproccnt; i++)
		ptmanager_fork(ptm, ppid, subprocs[i]);
#endif
}

static int
dispatch_kqproc(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	Manager *m = userdata;
	struct kevent kev;
	int nkev;
	struct timespec ts = { 0, 0 };

	nKev = kevent(ev->fd, NULL, 0, &kev, 1, &ts);

	if (nkev < 0) {
		log_error("Error waiting on Kernel Queue: %s\n",
			strerror(errno));
		return 0;
	} else if (nkev == 0) {
		log_warning("No events from Kernel Queue\n");
		return 0;
	}

	assert(kev.filter == EVFILT_PROC);

	if (kev.fflags & NOTE_CHILD)
		ptmanager_fork(m->pt_manager, kev.data, kev.ident);
	else if (kev.fflags & NOTE_EXIT)
		ptmanager_exit(m->pt_manager, kev.ident);
	else if (kev.fflags & NOTE_FORK)
		dispatch_note_fork(m->pt_manager, kev.ident);
	else if (kev.fflags & NOTE_TRACKERR)
		log_error("NOTE_TRACKERR received from Kernel Queue\n");
	else if (kev.fflags & NOTE_EXEC)
		log_debug("NOTE_EXEC was received");
}

int
manager_setup_kqproc_watch(Manager *m, int with_fd)
{
	int r;

	if (with_fd <= -1) {
		with_fd = kqueue();
		if (with_fd < 0) {
			log_error("Failed to open Kernel Queue: %m\n");
			return -errno;
		}
	}

	m->kqproc_fd = with_fd;

	r = sd_event_add_io(m->event, &m->kqproc_event_source, m->kqproc_fd,
		EPOLLIN, dispatch_kqproc, m);
	if (r < 0) {
		close(m->kqproc_fd);
		return r;
	}
	return 0;
}

extern int _ptgroup_move_or_add(PTGroup *grp, PTManager *ptm, pid_t pid);

int
ptgroup_attach(PTGroup *grp, PTManager *ptm, pid_t pid)
{
	int r = _ptgroup_move_or_add(grp, ptm, pid);
	struct kevent ev;

	if (r == 0)
		return 0; /* already tracked in that group */
	else if (r == 1)
		return 1; /* moved group, but already tracked */

	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, PROC_FILTER_FLAGS, 0, NULL);
	r = kevent(ptm->group.manager->kqproc_fd, &ev, 1, NULL, 0, NULL);

	if (r < 0) {
		log_error("Failed to watch PID %lld: %m", (long long)pid);
		return -errno;
	}

	return 1;
}
