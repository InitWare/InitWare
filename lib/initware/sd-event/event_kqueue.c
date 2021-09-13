/*
 * Copyright (c) 2021
 *	David MacKay.  All rights reserved.
 */
/*
 * Partial reimplementation of sd-event using BSD Kernel Queues instead of
 * epoll/timerfd/signalfd/eventfd.
 * Notes:
 *  - imperfect mapping of EPOLLRDHUP/EPOLLHUP;
 *  - only WEXITED for subprocess event sources
 *  - only monotonic timers
 */

#include <sys/event.h>

#include <stdbool.h>

#include "bsdqueue.h"
#include "sd-event.h"
#include "util.h"

typedef enum source_type {
	SOURCE_IO,
	SOURCE_TIMER,
	SOURCE_SIGNAL,
	SOURCE_SUBPROCESS,
	SOURCE_DEFER,
	SOURCE_POST,
	SOURCE_EXIT,
} source_type_t;

struct sd_event_source {
	size_t refcnt;

	LIST_ENTRY(sd_event_source) sources;

	source_type_t type;
	sd_evloop *loop;
	sd_event_source_enabled enabled;

	union {
		struct {
			sd_event_io_handler_t callback;
			int fd;
			uint32_t events;
		} io;
		struct {
			bool realtime;
			usec_t usec; /* absolute time of firing */
		} timer;
		struct {
			int signo;
		} signal;
		struct {
			pid_t pid;
		} subproc;
	};
};

struct sd_evloop {
	size_t refcnt;
	bool is_default;

	int kq;
	LIST_HEAD(sources, sd_event_source) sources;
};

static sd_evloop *default_loop;

static void
source_free(sd_event_source *source)
{
	/* DEREGISTER */
	LIST_REMOVE(source, sources);
	free(source);
}

int
sd_evloop_default(sd_evloop **out)
{
	int r;

	if (default_loop) {
		*out = default_loop;
		return 0;
	}

	r = sd_evloop_new(&default_loop);
	if (default_loop)
		default_loop->is_default = true;
	*out = default_loop;
	return r;
}

static void
loop_free(sd_evloop *loop)
{
	sd_event_source *source, *tmp;
	LIST_FOREACH_SAFE (source, &loop->sources, sources, tmp)
		source_free(source);
	close(loop->kq);
	free(loop);
}

int
sd_evloop_new(sd_evloop **out)
{
	sd_evloop *loop = new0(sd_evloop, 1);
	int r;

	if (!loop)
		return -ENOMEM;

	loop->refcnt = 1;

	loop->kq = kqueue();
	if (loop->kq < 0) {
		r = -errno;
		goto fail;
	}

fail:
	free(loop);
	return r;
}

sd_evloop *
sd_evloop_ref(sd_evloop *loop)
{
	loop->refcnt++;
	return loop;
}

sd_evloop *
sd_evloop_unref(sd_evloop *loop)
{
	if (!loop)
		return NULL;

	if (--loop->refcnt <= 0)
		loop_free(loop);

	return NULL;
}

static sd_event_source *
source_alloc(sd_evloop *loop, source_type_t type)
{
	sd_event_source *source = new0(sd_event_source, 1);

	if (!source)
		return NULL;

	source->refcnt = 1;
	source->type = type;
	source->enabled = SD_EVENT_OFF;
	source->loop = loop;

	return source;
}

static int
source_disable(sd_event_source *source)
{
	struct kevent kev;

	switch (source->type) {
	case SOURCE_IO: {
		EV_SET(&kev, source->io.fd, EVFILT_READ, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, NULL, 0, NULL);
		EV_SET(&kev, source->io.fd, EVFILT_WRITE, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, NULL, 0, NULL);
#ifdef EVFILT_EXCEPT
		EV_SET(&kev, source->io.fd, EVFILT_EXCEPT, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, NULL, 0, NULL);
#endif
	}

	case SOURCE_TIMER: {
		EV_SET(&kev, (uintptr_t)source, EVFILT_TIMER, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
	}

	case SOURCE_SIGNAL: {
		EV_SET(&kev, source->signal.signo, EVFILT_SIGNAL, EV_DELETE, 0,
			0, source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
	}

	case SOURCE_SUBPROCESS: {
		EV_SET(&kev, source->subproc.pid, EVFILT_PROC, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
	}

	default:
		abort();
	}

	source->enabled = SD_EVENT_OFF;
	return 1;
}

static int
source_enable(sd_event_source *source, bool is_oneshot)
{
	int r;
	struct kevent kev;
	int oneshot = is_oneshot ? EV_ONESHOT : 0;

	switch (source->type) {
	case SOURCE_IO:
		if (source->io.events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) {
			EV_SET(&kev, source->io.fd, EVFILT_READ,
				EV_ADD | oneshot, 0, 0, source);
			r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
			if (r < 0)
				goto fail;
		}
		if (source->io.events & (EPOLLOUT)) {
			EV_SET(&kev, source->io.fd, EVFILT_WRITE,
				EV_ADD | oneshot, 0, 0, source);
			r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
			if (r < 0)
				goto fail;
		}
		if (source->io.events & EPOLLPRI) {
#ifdef EVFILT_EXCEPT
			EV_SET(&kev, source->io.fd, EVFILT_EXCEPT,
				EV_ADD | oneshot, 0, 0, source);
			r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
			if (r < 0)
				goto fail;
#else
			log_warning("EVFILT_EXCEPT absent.");
#endif
		}

	case SOURCE_TIMER: {
		usec_t rel = (source->timer.realtime ? now(CLOCK_MONOTONIC) :
							     now(CLOCK_MONOTONIC)) -
			source->timer.usec;

		EV_SET(&kev, (uintptr_t)source, EVFILT_TIMER, EV_ADD | oneshot,
			0, 0, source);
		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;
	}

	case SOURCE_SIGNAL:
		EV_SET(&kev, source->signal.signo, EVFILT_SIGNAL,
			EV_ADD | oneshot, 0, 0, source);

		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;

	case SOURCE_SUBPROCESS:
		EV_SET(&kev, source->subproc.pid, EVFILT_PROC, EV_ADD,
			NOTE_EXIT, 0, source);
		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;

	default:
		abort();
	}

	source->enabled = is_oneshot ? SD_EVENT_ONESHOT : SD_ON;

	return 1;

fail:
	source_disable(source);
	return r;
}

int
sd_event_source_set_enabled(sd_event_source *source, int enabled)
{
	if (source->enabled == enabled)
		return 0;
	else if (enabled == SD_EVENT_OFF)
		return source_disable(source);
	else if (enabled == SD_EVENT_ONESHOT)
		return source_enable(source, true);
	else if (enabled == SD_EVENT_ON)
		return source_enable(source, false);
}
