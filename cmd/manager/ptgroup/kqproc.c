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

#include <sys/epoll.h>
#include <sys/event.h>

#include "kqproc.h"
#include "manager.h"

int manager_setup_kqproc_watch(Manager *m) {
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = &m->kqproc_watch,
        };
        int r;

        m->kqproc_watch.type = WATCH_KQPROC;
        m->kqproc_watch.fd = kqueue();
        if (m->kqproc_watch.fd < 0) {
                log_error("Failed to open Kernel Queue: %m\n");
                return -errno;
        }

        r = epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->kqproc_watch.fd, &ev);
        if (r < 0) {
                log_error("Failed to add Kernel Queue for PROC events to epoll: %m");
                return -errno;
        }

        return 0;
}

void manager_kqproc_event(Manager *m) {
        struct kevent ev;
        int nEv;
        struct timespec ts = { 0, 0 };

        nEv = kevent(m->kqproc_watch.fd, NULL, 0, &ev, 1, &ts);

        if (nEv < 0)
        {
                log_error("Error waiting on PROC Kernel Queue: %s\n", strerror(errno));
                return;
        }
        else if (!nEv)
        {
                log_warning("No events from PROC Kernel Queue\n");
                return;
        }

        assert(ev.filter == EVFILT_PROC);

        if (ev.fflags & NOTE_CHILD)
                ptmanager_fork(m->pt_manager, ev.data, ev.ident);
        else if (ev.fflags & NOTE_EXIT)
                ptmanager_exit(m->pt_manager, ev.ident);
        else if (ev.fflags  & NOTE_TRACKERR)
                log_error("NOTE_TRACKERR received from Kernel Queue\n");
}


extern int _ptgroup_move_or_add(PTGroup *grp, PTManager *ptm, pid_t pid);

int ptgroup_attach(PTGroup *grp, PTManager *ptm, pid_t pid) {
        int r = _ptgroup_move_or_add(grp, ptm, pid);
        struct kevent ev;

        if (r == 0)
                return 0; /* already tracked in that group */
        else if (r == 1)
                return 1; /* moved group, but already tracked */

        EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_TRACK, 0, NULL);
        r = kevent(ptm->manager->kqproc_watch.fd, &ev, 1, NULL, 0, NULL);

        if (r < 0) {
                log_error("Failed to watch PID %lld: %m", (long long) pid);
                return -errno;
        }

        return 1;
}