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
 * todo:
 *  - 'floating' events (don't ref on return)
 *  - use NOTE_ABSTIME on FreeBSD
 *  - use EV_DISABLE instead of EV_ADD and EV_DELETE all the time
 *  - timer coalescence with a heap
 *  - only FreeBSD and Mac OS X reset timers properly when changed
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/wait.h>

#include <stdbool.h>

#include "bsdqueue.h"
#include "bsdsignal.h"
#include "sd-event.h"
#include "util.h"

#define LIST_INSERT_SORTED(head, elm, type, field, comparator)                 \
	do {                                                                   \
		struct type *curelm, *tmpelm;                                  \
		if (LIST_EMPTY(head)) /* empty list */                         \
		{                                                              \
			LIST_INSERT_HEAD(head, elm, field);                    \
			goto done;                                             \
		}                                                              \
		LIST_FOREACH (curelm, head, field) {                           \
			int r = comparator(elm, curelm);                       \
			if (r < 0) {                                           \
				LIST_INSERT_BEFORE(curelm, elm, field);        \
				goto done;                                     \
			} else if (r == 0)                                     \
				goto done; /* already present */               \
			tmpelm = curelm;                                       \
		}                                                              \
		LIST_INSERT_AFTER(tmpelm, elm, field);                         \
	done:                                                                  \
		break;                                                         \
	} while (0)

typedef enum source_type {
	/**
	 * POLLIN/OUT/HUP/... on a file descriptor. Defaults to ON.
	 */
	SOURCE_IO,
	/**
	 * Absolute timer. Defaults to ONESHOT.
	 */
	SOURCE_TIMER,
	/**
	 * Signal. Defaults to ON.
	 */
	SOURCE_SIGNAL,
	/**
	 * Subprocess exit. Defaults to ON
	 */
	SOURCE_SUBPROCESS,
	/**
	 * Pre-waiting work. Defaults to ONESHOT. Runs immediately before
	 * waiting for events from KQueue.
	 */
	SOURCE_DEFER,
	/**
	 * Post-waiting work. Defaults to ON. Runs after all handlers for other
	 * event sources were processed after waiting.
	 */
	SOURCE_POST,
	/**
	 * Pre-exit work. ON/ONESHOT irrelevant. Runs on event loop exit.
	 */
	SOURCE_EXIT,
} source_type_t;

struct sd_event_source {
	size_t refcnt;

	LIST_ENTRY(sd_event_source) sources;
	LIST_ENTRY(sd_event_source) prepares;

	LIST_ENTRY(sd_event_source) pendings;
	bool is_pending;

	char *description;
	source_type_t type;
	sd_event *loop;
	uint64_t priority;
	sd_event_source_enabled_t enabled;
	void *userdata;

	/**
	 * Preparation callback. Runs before event loop waits, if event is
	 * enabled. TODO: Deal with cases where prepare callback in turn enables
	 * further events which have preparation to do.
	 */
	sd_event_handler_t prepare_callback;

	union {
		struct {
			sd_event_io_handler_t callback;
			int fd;
			uint32_t events;
			uint32_t revents;
		} io;
		struct {
			sd_event_time_handler_t callback;

			bool realtime;
			usec_t usec; /* absolute time of firing */
		} timer;
		struct {
			LIST_ENTRY(sd_event_source) signals;

			sd_event_signal_handler_t callback;
			int signo;
		} signal;
		struct {
			sd_event_child_handler_t callback;

			pid_t pid;
			int status; /* wait status */
		} subproc;
		struct {
			LIST_ENTRY(sd_event_source) defers;

			sd_event_handler_t callback;
		} defer;
		struct {
			LIST_ENTRY(sd_event_source) posts;

			sd_event_handler_t callback;
		} post;
		struct {
			LIST_ENTRY(sd_event_source) exits;

			sd_event_handler_t callback;
		} exit;
	};
};

struct sd_event {
	size_t refcnt;
	bool is_default;
	sd_event_loop_status_t state;

	bool should_exit;
	int exit_code;

	uint64_t ts_monotonic; /* monotonic time of last poll */
	uint64_t ts_realtime; /* realtime time of last poll */

	int kq;

	LIST_HEAD(sources, sd_event_source) sources;
	LIST_HEAD(prepares, sd_event_source) prepares;
	LIST_HEAD(pendings, sd_event_source) pendings;
	LIST_HEAD(signals, sd_event_source) signals;
	LIST_HEAD(defers, sd_event_source) defers;
	LIST_HEAD(posts, sd_event_source) posts;
	LIST_HEAD(exits, sd_event_source) exits;
};

static sd_event *default_loop;

static int
pending_comparator(const void *a, const void *b)
{
	const sd_event_source *eva = a, *evb = b;
	int r;

	r = CMP(eva->priority, evb->priority);
	if (r != 0)
		return r;

	return CMP(eva, evb);
}

static void
source_free(sd_event_source *source)
{
	/* deregister */
	sd_event_source_set_enabled(source, SD_EVENT_OFF);

	switch (source->type) {
	case SOURCE_SIGNAL:
		LIST_REMOVE(source, signal.signals);
		break;

	case SOURCE_DEFER:
		LIST_REMOVE(source, defer.defers);
		break;

	case SOURCE_POST:
		LIST_REMOVE(source, post.posts);
		break;

	case SOURCE_EXIT:
		LIST_REMOVE(source, exit.exits);

	default:
		break;
	}

	if (source->prepare_callback)
		LIST_REMOVE(source, prepares);

	LIST_REMOVE(source, sources);

	free(source->description);
	free(source);
}

int
sd_event_default(sd_event **out)
{
	int r;

	if (default_loop) {
		*out = default_loop;
		return 0;
	}

	r = sd_event_new(&default_loop);
	if (default_loop)
		default_loop->is_default = true;
	*out = default_loop;
	return r;
}

static void
loop_free(sd_event *loop)
{
	sd_event_source *source, *tmp;
	LIST_FOREACH_SAFE (source, &loop->sources, sources, tmp) {
		sd_event_source_unref(source);
	}
	close(loop->kq);
	free(loop);
}

int
sd_event_new(sd_event **out)
{
	sd_event *loop = new0(sd_event, 1);
	int r;

	if (!loop)
		return -ENOMEM;

	loop->refcnt = 1;

	loop->kq = kqueue();
	if (loop->kq < 0) {
		r = -errno;
		goto fail;
	}

	*out = loop;

	return 0;

fail:
	free(loop);
	return r;
}

sd_event *
sd_event_ref(sd_event *loop)
{
	loop->refcnt++;
	return loop;
}

sd_event *
sd_event_unref(sd_event *loop)
{
	if (!loop)
		return NULL;

	if (--loop->refcnt <= 0)
		loop_free(loop);

	return NULL;
}

sd_event_source *
sd_event_source_ref(sd_event_source *source)
{
	source->refcnt++;

	return source;
}

sd_event_source *
sd_event_source_unref(sd_event_source *source)
{
	if (!source)
		return NULL;

	if (--source->refcnt <= 0)
		source_free(source);

	return NULL;
}

int
sd_event_exit(sd_event *loop, int code)
{
	loop->should_exit = true;
	loop->exit_code = code;
	return 0;
}

int
sd_event_get_state(sd_event *loop)
{
	return loop->state;
}

int
sd_event_get_exit_code(sd_event *loop, int *out)
{
	// TODO
	*out = 0;
	return 0;
}

int
sd_event_get_iteration(sd_event *loop, uint64_t *out)
{
	// TODO
	*out = 1;
	return 0;
}

int
sd_event_get_tid(sd_event *loop, pid_t *out)
{
	// TODO
	*out = getpid();
	return 0;
}

int
sd_event_now(sd_event *loop, clockid_t clock, uint64_t *out)
{
	if (loop->ts_monotonic == 0)
		return -ENODATA; /* if not set, loop yet to run */

	switch (clock) {
	case CLOCK_REALTIME:
		*out = loop->ts_realtime;
		break;

	case CLOCK_MONOTONIC:
		*out = loop->ts_monotonic;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/* Returns a new source object - generic fields are initialised, not others. */
static sd_event_source *
source_alloc(sd_event *loop, source_type_t type, void *userdata)
{
	sd_event_source *source = new0(sd_event_source, 1);

	if (!source)
		return NULL;

	source->refcnt = 1;
	source->type = type;
	source->enabled = SD_EVENT_OFF;
	source->loop = loop;
	source->userdata = userdata;

	LIST_INSERT_HEAD(&loop->sources, source, sources);

	switch (type) {
	case SOURCE_SIGNAL:
		LIST_INSERT_HEAD(&loop->signals, source, signal.signals);
		break;

	case SOURCE_DEFER:
		LIST_INSERT_HEAD(&loop->defers, source, defer.defers);
		break;

	case SOURCE_POST:
		LIST_INSERT_HEAD(&loop->posts, source, post.posts);
		break;

	case SOURCE_EXIT:
		LIST_INSERT_HEAD(&loop->exits, source, exit.exits);

	default:
		break;
	}

	return source;
}

static int
source_disable(sd_event_source *source)
{
	struct kevent kev;

	if (source->enabled == SD_EVENT_OFF)
		return 0;

	log_trace("Disable event %s\n", source->description);

	switch (source->type) {
	case SOURCE_IO: {
		log_trace("Disable I/O event %s on FD %d\n",
			source->description, source->io.fd);

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
		break;
	}

	case SOURCE_TIMER: {
		EV_SET(&kev, (uintptr_t)source, EVFILT_TIMER, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		break;
	}

	case SOURCE_SIGNAL: {
		EV_SET(&kev, source->signal.signo, EVFILT_SIGNAL, EV_DELETE, 0,
			0, source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		break;
	}

	case SOURCE_SUBPROCESS: {
		EV_SET(&kev, source->subproc.pid, EVFILT_PROC, EV_DELETE, 0, 0,
			source);
		kevent(source->loop->kq, &kev, 1, 0, 0, 0);
	}

	default:
		break;
	}

	source->enabled = SD_EVENT_OFF;
	if (source->is_pending) {
		LIST_REMOVE(source, pendings);
		source->is_pending = false;
	}
	return 1;
}

static int
source_enable(sd_event_source *source, bool is_oneshot)
{
	int r;
	struct kevent kev;
	int oneshot = is_oneshot ? EV_ONESHOT : 0;

	log_trace("Enable event %s\n", source->description);

	switch (source->type) {
	case SOURCE_IO:
		log_trace("Enable I/O event %s on FD %d\n", source->description,
			source->io.fd);
		if (source->io.events & EPOLLIN ||
			source->io.events & EPOLLHUP ||
			source->io.events & EPOLLRDHUP) {
			EV_SET(&kev, source->io.fd, EVFILT_READ,
				EV_ADD | oneshot, 0, 0, source);
			r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
			if (r < 0)
				goto fail;
		}
		if (source->io.events & EPOLLOUT) {
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
			break;
		}
		break;

	case SOURCE_TIMER: {
		usec_t rel;
		usec_t cur = source->timer.realtime ? now(CLOCK_MONOTONIC) :
							    now(CLOCK_MONOTONIC);
		rel = source->timer.usec <= cur ? 1 : source->timer.usec - cur;

		if (rel != 1)
			rel /= USEC_PER_MSEC; /* EVFILT_TIMER uses millisecs */

		EV_SET(&kev, (uintptr_t)source, EVFILT_TIMER, EV_ADD | oneshot,
			0, rel, source);
		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;
		break;
	}

	case SOURCE_SIGNAL:
		EV_SET(&kev, source->signal.signo, EVFILT_SIGNAL,
			EV_ADD | oneshot, 0, 0, source);

		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;
		break;

	case SOURCE_SUBPROCESS:
		EV_SET(&kev, source->subproc.pid, EVFILT_PROC, EV_ADD,
			NOTE_EXIT, 0, source);
		r = kevent(source->loop->kq, &kev, 1, 0, 0, 0);
		if (r < 0)
			goto fail;

	default:
		break;
	}

	source->enabled = is_oneshot ? SD_EVENT_ONESHOT : SD_EVENT_ON;

	return 1;

fail:
	log_error("Failed to add event: %m");
	source_disable(source);
	return r;
}

int
sd_event_source_set_description(sd_event_source *source,
	const char *description)
{
	return free_and_strdup(&source->description, description);
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
	else /* enabled == SD_EVENT_ON */
		return source_enable(source, false);
}

int
sd_event_source_set_priority(sd_event_source *source, int64_t priority)
{
	source->priority = priority;
	LIST_REMOVE(source, sources);
	LIST_INSERT_SORTED(&source->loop->sources, source, sd_event_source,
		sources, pending_comparator);
	return 0;
}

int
sd_event_source_set_prepare(sd_event_source *source,
	sd_event_handler_t callback)
{
	bool hadcallback = source->prepare_callback;

	if (hadcallback && !callback)
		LIST_REMOVE(source, prepares);
	source->prepare_callback = callback;
	if (!hadcallback && callback)
		LIST_INSERT_SORTED(&source->loop->prepares, source,
			sd_event_source, prepares, pending_comparator);
	return 0;
}

/*
 * Event adding functions
 */

int
sd_event_add_io(sd_event *loop, sd_event_source **out, int fd, uint32_t events,
	sd_event_io_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *io = source_alloc(loop, SOURCE_IO, userdata);

	if (!io)
		return -ENOMEM;

	io->io.fd = fd;
	io->io.events = events;
	io->io.callback = callback;

	r = sd_event_source_set_enabled(io, SD_EVENT_ON);
	if (!r) {
		source_free(io);
		return r;
	}

	if (out)
		*out = io;

	return 0;
}

int
sd_event_source_set_io_fd(sd_event_source *source, int fd)
{
	int prevenabled = source->enabled;

	source_disable(source);
	source->io.fd = fd;
	return sd_event_source_set_enabled(source, prevenabled);
}

int
sd_event_source_set_io_events(sd_event_source *source, uint32_t events)
{
	int prevenabled = source->enabled;

	source_disable(source);
	source->io.events = events;
	return sd_event_source_set_enabled(source, prevenabled);
}

int
sd_event_add_time(sd_event *loop, sd_event_source **out, clockid_t clock,
	uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback,
	void *userdata)
{
	int r;
	sd_event_source *time = source_alloc(loop, SOURCE_TIMER, userdata);

	if (!time)
		return -ENOMEM;

	time->timer.callback = callback;
	time->timer.usec = usec;
	if (clock == CLOCK_REALTIME) {
		log_warning("REALTIME clocks not supported on this platform");
		time->timer.realtime = true;
	}

	r = sd_event_source_set_enabled(time, SD_EVENT_ONESHOT);
	if (!r) {
		source_free(time);
		return r;
	}

	if (out)
		*out = time;

	return 0;
}

int
sd_event_source_set_time(sd_event_source *source, uint64_t usec)
{
	int prevenabled = source->enabled;

	source_disable(source);
	source->timer.usec = usec;
	return sd_event_source_set_enabled(source, prevenabled);
}

int
sd_event_source_get_time(sd_event_source *source, uint64_t *out)
{
	*out = source->timer.usec;
	return 0;
}

int
sd_event_add_signal(sd_event *loop, sd_event_source **out, int signo,
	sd_event_signal_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *sig = source_alloc(loop, SOURCE_SIGNAL, userdata);

	if (!sig)
		return -ENOMEM;

	sig->signal.callback = callback;
	sig->signal.signo = signo;

	r = sd_event_source_set_enabled(sig, SD_EVENT_ON);
	if (!sig) {
		source_free(sig);
		return r;
	}

	if (out)
		*out = sig;

	return 0;
}

int
sd_event_add_child(sd_event *loop, sd_event_source **out, pid_t pid,
	int options, sd_event_child_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *source = source_alloc(loop, SOURCE_SUBPROCESS,
		userdata);

	if (!source)
		return -ENOMEM;

	source->subproc.callback = callback;

	r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
	if (!source) {
		source_free(source);
		return r;
	}

	if (out)
		*out = source;

	return 0;
}

int
sd_event_add_defer(sd_event *loop, sd_event_source **out,
	sd_event_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *source = source_alloc(loop, SOURCE_DEFER, userdata);

	if (!source)
		return -ENOMEM;

	source->defer.callback = callback;

	r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
	if (!source) {
		source_free(source);
		return r;
	}

	if (out)
		*out = source;

	return 0;
}

int
sd_event_add_post(sd_event *loop, sd_event_source **out,
	sd_event_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *source = source_alloc(loop, SOURCE_POST, userdata);

	if (!source)
		return -ENOMEM;

	source->post.callback = callback;

	r = sd_event_source_set_enabled(source, SD_EVENT_ON);
	if (!source) {
		source_free(source);
		return r;
	}

	if (out)
		*out = source;

	return 0;
}

int
sd_event_add_exit(sd_event *loop, sd_event_source **out,
	sd_event_handler_t callback, void *userdata)
{
	int r;
	sd_event_source *source = source_alloc(loop, SOURCE_EXIT, userdata);

	if (!source)
		return -ENOMEM;

	source->exit.callback = callback;

	r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
	if (!source) {
		source_free(source);
		return r;
	}

	if (out)
		*out = source;

	return 0;
}

static void
source_clear(sd_event_source *source)
{
	switch (source->type) {
	case SOURCE_IO:
		source->io.revents = 0;

	default:
		break;
	}
}

static int
loop_kevent(sd_event *loop, usec_t timeout)
{
	struct kevent kevs[16];
	int r;
	struct timespec ts;

	loop->ts_realtime = now(CLOCK_REALTIME);
	loop->ts_monotonic = now(CLOCK_MONOTONIC);
	timespec_store(&ts, timeout);

	r = kevent(loop->kq, NULL, 0, kevs, 16, timeout == -1 ? NULL : &ts);
	log_trace("KEvent returned %d", r);
	if (r <= 0)
		return r;

	for (int i = 0; i < r; i++) {
		struct kevent *kev = &kevs[i];
		sd_event_source *source = (sd_event_source *)kev->udata;

		switch (source->type) {
		case SOURCE_IO:
		{
			int rdhup = source->io.events & EPOLLRDHUP? EPOLLRDHUP : 0;

			if (kev->filter == EVFILT_WRITE) {
				if (kev->data)
					source->io.revents |= EPOLLOUT;
				if (kev->flags & EV_EOF)
					source->io.revents |= EPOLLERR;
			} else if (kev->filter == EVFILT_READ) {
				if (kev->data)
					source->io.revents |= EPOLLIN;
				if (kev->flags & EV_EOF)
					source->io.revents |= EPOLLHUP |
						rdhup;
			}
#ifdef EVFILT_EXCEPT
			else if (kev->filter == EVFILT_EXCEPT)
				if (kev->fflags & NOTE_OOB)
					source->io.revents |= EPOLLPRI;
#endif

			break;
		}

		case SOURCE_SUBPROCESS:
			source->subproc.status = kev->data;

		default:
			break;
		}

		LIST_INSERT_SORTED(&loop->pendings, source, sd_event_source,
			pendings, pending_comparator);
		source->is_pending = true;
	}

	return r;
}

int
sd_event_prepare(sd_event *loop)
{
	sd_event_source *prepare, *defer;
	int r, ndefers = 0;

	if (loop->should_exit) {
		loop->state = SD_EVENT_PENDING;
		return 1;
	}

	log_trace("Running prepare callbacks");
	LIST_FOREACH (prepare, &loop->prepares, prepares) {
		if (prepare->enabled == SD_EVENT_OFF)
			continue;
		r = prepare->prepare_callback(prepare, prepare->userdata);
		if (r < 0)
			return r;
		else if (r == 0) {
			log_trace(
				"Source %s prepare-callback returned 0, disabling",
				prepare->description);
			source_disable(prepare);
		}
	}

	/* queue up defers */
	log_trace("Running defer callbacks");
	LIST_FOREACH (defer, &loop->defers, defer.defers)
		if (defer->enabled != SD_EVENT_OFF) {
			LIST_INSERT_SORTED(&loop->pendings, defer,
				sd_event_source, pendings, pending_comparator);
			defer->is_pending = true;
			ndefers++;
		}

	/* run kevent with no timeout */
	r = loop_kevent(loop, 0);
	if (r < 0)
		loop->state = SD_EVENT_INITIAL;
	else if (r == 0 && ndefers == 0)
		loop->state = SD_EVENT_ARMED;
	else {
		loop->state = SD_EVENT_PENDING;
		return r + ndefers;
	}

	return r;
}

int
sd_event_wait(sd_event *loop, usec_t timeout)
{
	int r;
	sd_event_source *post;

	assert(loop->state == SD_EVENT_ARMED);

	if (loop->should_exit) {
		loop->state = SD_EVENT_PENDING;
		return 1;
	}

	r = loop_kevent(loop, timeout);
	if (r <= 0) {
		loop->state = SD_EVENT_INITIAL;
		return r;
	}

	loop->state = SD_EVENT_PENDING;

	/* at least one event waiting; queue up posts */
	LIST_FOREACH (post, &loop->posts, post.posts)
		if (post->enabled != SD_EVENT_OFF) {
			LIST_INSERT_SORTED(&loop->pendings, post,
				sd_event_source, pendings, pending_comparator);
			post->is_pending = true;
			r++;
		}

	return r;
}

static int
source_dispatch(sd_event_source *source)
{
	int r;

	switch (source->type) {
	case SOURCE_IO:
		r = source->io.callback(source, source->io.fd,
			source->io.revents, source->userdata);
		break;

	case SOURCE_TIMER:
		r = source->timer.callback(source, source->timer.usec,
			source->userdata);
		break;

	case SOURCE_SIGNAL:
		r = source->signal.callback(source, NULL, source->userdata);
		break;

	case SOURCE_SUBPROCESS: {
		siginfo_t siginfo = waitstat_to_siginfo(source->subproc.pid,
			source->subproc.status);

#if 0
		waitid(P_PID, source->subproc.pid, &siginfo, WNOWAIT);
#endif
		r = source->subproc.callback(source, &siginfo,
			source->userdata);
		waitid(P_PID, source->subproc.pid, NULL, 0);
		break;
	}

	case SOURCE_DEFER:
		r = source->defer.callback(source, source->userdata);
		break;

	case SOURCE_POST:
		r = source->post.callback(source, source->userdata);
		break;

	case SOURCE_EXIT:
		r = source->exit.callback(source, source->userdata);
	}

	source_clear(source);

	return r;
}

int
sd_event_dispatch(sd_event *loop)
{
	sd_event_source *source, *tmp;
	int r = 0;

	assert(loop->state == SD_EVENT_PENDING);

	if (loop->should_exit) {
		log_trace("Dispatching exit sources");

		LIST_FOREACH (source, &loop->exits, exit.exits) {
			if (source->enabled != SD_EVENT_OFF)
				r = source_dispatch(source);
			if (r < 0)
				return r;
		}
		log_trace("Event loop finished");

		loop->state = SD_EVENT_FINISHED;
		return 0;
	}

	LIST_FOREACH_SAFE (source, &loop->pendings, pendings, tmp) {
		sd_event_source_ref(source);
		log_trace("Dispatching source %s/%p", source->description,
			source);
		r = source_dispatch(source);
		if (r < 0)
			return r;
		else if (source->enabled == SD_EVENT_ONESHOT)
			sd_event_source_set_enabled(source, SD_EVENT_OFF);

		source->is_pending = false;
		LIST_REMOVE(source, pendings);
		sd_event_source_unref(source);
	}

	return r;
}

_public_ int
sd_event_run(sd_event *loop, uint64_t timeout)
{
	int r;

	r = sd_event_prepare(loop);
	if (r > 0)
		return sd_event_dispatch(loop);
	else if (r < 0)
		return r;

	r = sd_event_wait(loop, timeout);
	if (r > 0)
		return sd_event_dispatch(loop);
	else
		return r;
}