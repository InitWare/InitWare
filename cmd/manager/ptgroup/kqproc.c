/*******************************************************************

    LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

    (c) 2021 David Mackay
        All rights reserved.
*********************************************************************/

#include <sys/types.h>
#include <sys/event.h>

#include "kqproc.h"
#include "manager.h"

#ifdef Sys_Plat_MacOS
#include <libproc.h>

#define PROC_FILTER_FLAGS NOTE_EXIT | NOTE_FORK
#else
#define PROC_FILTER_FLAGS NOTE_EXIT | NOTE_TRACK
#define NOTE_EXITSTATUS 0
#endif

static void dispatch_note_fork(PTManager *ptm, int ppid)
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

		EV_SET(&kev, subprocs[i], EVFILT_PROC, EV_ADD, PROC_FILTER_FLAGS, 0, NULL);
		r = kevent(ptm->group.manager->kqproc_io.fd, &kev, 1, NULL, 0, NULL);

		// FIXME: By rights, we shouldn't do any I/O in this loop.
		if (r < 0)
			log_error("Failed to watch PID %lld: %m", (long long) subprocs[i]);
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

static void kqproc_io_cb(struct ev_loop *evloop, ev_io *ev, int revents)
{
        Manager *m = ev->data;
        struct kevent kev;
        int nKev;
        struct timespec ts = { 0, 0 };

        nKev = kevent(ev->fd, NULL, 0, &kev, 1, &ts);

        if (nKev < 0) {
                log_error("Error waiting on PROC Kernel Queue: %s\n", strerror(errno));
                return;
        } else if (!nKev) {
                log_warning("No events from PROC Kernel Queue\n");
                return;
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


int manager_setup_kqproc_watch(Manager *m, int with_fd)
{
        if (with_fd <= -1) {
                with_fd = kqueue();
                if (with_fd < 0) {
                        log_error("Failed to open Kernel Queue: %m\n");
                        return -errno;
                }
        }

        ev_io_init(&m->kqproc_io, kqproc_io_cb, with_fd, EV_READ);
        m->kqproc_io.data = m;
        ev_io_start(m->evloop, &m->kqproc_io);
        return 0;
}

extern int _ptgroup_move_or_add(PTGroup *grp, PTManager *ptm, pid_t pid);

int ptgroup_attach(PTGroup *grp, PTManager *ptm, pid_t pid)
{
        int r = _ptgroup_move_or_add(grp, ptm, pid);
        struct kevent ev;

        if (r == 0)
                return 0; /* already tracked in that group */
        else if (r == 1)
                return 1; /* moved group, but already tracked */

	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, PROC_FILTER_FLAGS, 0, NULL);
	r = kevent(ptm->group.manager->kqproc_io.fd, &ev, 1, NULL, 0, NULL);

	if (r < 0) {
		log_error("Failed to watch PID %lld: %m", (long long) pid);
		return -errno;
	}

	return 1;
}
