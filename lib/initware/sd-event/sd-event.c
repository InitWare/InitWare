/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/timerfd.h>
#include <sys/wait.h>
#include <pthread.h>

#include "alloc-util.h"
#include "bsdglibc.h"
#include "errno-util.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "inotify-util.h"
#include "list.h"
#include "logarithm.h"
#include "macro.h"
#include "missing.h"
#include "origin-id.h"
#include "prioq.h"
#include "sd-daemon.h"
#include "sd-id128.h"
#include "set.h"
#include "string-table.h"
#include "strxcpyx.h"
#include "time-util.h"
#include "util.h"

#include "sd-event.h"

#ifdef HAVE_PIDFD_OPEN
#include <sys/pidfd.h>
#endif

#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

typedef enum EventSourceType {
        SOURCE_IO,
        SOURCE_TIME_REALTIME,
        SOURCE_TIME_BOOTTIME,
        SOURCE_TIME_MONOTONIC,
        SOURCE_TIME_REALTIME_ALARM,
        SOURCE_TIME_BOOTTIME_ALARM,
        SOURCE_SIGNAL,
        SOURCE_CHILD,
        SOURCE_DEFER,
        SOURCE_POST,
        SOURCE_EXIT,
        SOURCE_WATCHDOG,
        SOURCE_INOTIFY,
        SOURCE_MEMORY_PRESSURE,
        _SOURCE_EVENT_SOURCE_TYPE_MAX,
        _SOURCE_EVENT_SOURCE_TYPE_INVALID = -EINVAL,
} EventSourceType;

static const char* const event_source_type_table[_SOURCE_EVENT_SOURCE_TYPE_MAX] = {
        [SOURCE_IO]                  = "io",
        [SOURCE_TIME_REALTIME]       = "realtime",
        [SOURCE_TIME_BOOTTIME]       = "boottime",
        [SOURCE_TIME_MONOTONIC]      = "monotonic",
        [SOURCE_TIME_REALTIME_ALARM] = "realtime-alarm",
        [SOURCE_TIME_BOOTTIME_ALARM] = "boottime-alarm",
        [SOURCE_SIGNAL]              = "signal",
        [SOURCE_CHILD]               = "child",
        [SOURCE_DEFER]               = "defer",
        [SOURCE_POST]                = "post",
        [SOURCE_EXIT]                = "exit",
        [SOURCE_WATCHDOG]            = "watchdog",
        [SOURCE_INOTIFY]             = "inotify",
        [SOURCE_MEMORY_PRESSURE]     = "memory-pressure",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(event_source_type, int);

#define EVENT_SOURCE_IS_TIME(t)                                                \
	IN_SET((t), SOURCE_TIME_REALTIME, SOURCE_TIME_BOOTTIME,                \
		SOURCE_TIME_MONOTONIC, SOURCE_TIME_REALTIME_ALARM,             \
		SOURCE_TIME_BOOTTIME_ALARM)

/* All objects we use in epoll events start with this value, so that
 * we know how to dispatch it */
typedef enum WakeupType {
        WAKEUP_NONE,
        WAKEUP_EVENT_SOURCE, /* either I/O or pidfd wakeup */
        WAKEUP_CLOCK_DATA,
        WAKEUP_SIGNAL_DATA,
        WAKEUP_INOTIFY_DATA,
        _WAKEUP_TYPE_MAX,
        _WAKEUP_TYPE_INVALID = -EINVAL,
} WakeupType;

struct sd_event_source {
        WakeupType wakeup;

        unsigned n_ref;

        sd_event *event;
        void *userdata;
        sd_event_handler_t prepare;

        char *description;

        EventSourceType type;
        signed int enabled:3;
        bool pending:1;
        bool dispatching:1;
        bool floating:1;
        bool exit_on_failure:1;
        bool ratelimited:1;

        int64_t priority;
        unsigned pending_index;
        unsigned prepare_index;
        uint64_t pending_iteration;
        uint64_t prepare_iteration;

        sd_event_destroy_t destroy_callback;
        sd_event_handler_t ratelimit_expire_callback;

        LIST_FIELDS(sd_event_source, sources);

        RateLimit rate_limit;

        /* These are primarily fields relevant for time event sources, but since any event source can
         * effectively become one when rate-limited, this is part of the common fields. */
        unsigned earliest_index;
        unsigned latest_index;

        union {
                struct {
                        sd_event_io_handler_t callback;
                        int fd;
                        uint32_t events;
                        uint32_t revents;
                        bool registered:1;
                        bool owned:1;
                } io;
                struct {
                        sd_event_time_handler_t callback;
                        usec_t next, accuracy;
                } time;
                struct {
                        sd_event_signal_handler_t callback;
                        struct signalfd_siginfo siginfo;
                        int sig;
                        bool unblock;
                } signal;
                struct {
                        sd_event_child_handler_t callback;
                        siginfo_t siginfo;
                        pid_t pid;
                        int options;
                        int pidfd;
                        bool registered:1; /* whether the pidfd is registered in the epoll */
                        bool pidfd_owned:1; /* close pidfd when event source is freed */
                        bool process_owned:1; /* kill+reap process when event source is freed */
                        bool exited:1; /* true if process exited (i.e. if there's value in SIGKILLing it if we want to get rid of it) */
                        bool waited:1; /* true if process was waited for (i.e. if there's value in waitid(P_PID)'ing it if we want to get rid of it) */
                } child;
                struct {
                        sd_event_handler_t callback;
                } defer;
                struct {
                        sd_event_handler_t callback;
                } post;
                struct {
                        sd_event_handler_t callback;
                        unsigned prioq_index;
                } exit;
                struct {
                        sd_event_inotify_handler_t callback;
                        uint32_t mask;
                        struct inode_data *inode_data;
                        LIST_FIELDS(sd_event_source, by_inode_data);
                } inotify;
                struct {
                        int fd;
                        sd_event_handler_t callback;
                        void *write_buffer;
                        size_t write_buffer_size;
                        uint32_t events, revents;
                        LIST_FIELDS(sd_event_source, write_list);
                        bool registered:1;
                        bool locked:1;
                        bool in_write_list:1;
                } memory_pressure;
        };
};

// struct sd_event_source {
// 	unsigned n_ref;

// 	sd_event *event;
// 	void *userdata;
// 	sd_event_handler_t prepare;

// 	char *description;

// 	EventSourceType type: 5;
// 	signed int enabled: 3;
// 	bool pending: 1;
// 	bool dispatching: 1;
// 	bool floating: 1;

// 	int64_t priority;
// 	unsigned pending_index;
// 	unsigned prepare_index;
// 	uint64_t pending_iteration;
// 	uint64_t prepare_iteration;

// 	LIST_FIELDS(sd_event_source, sources);

// 	union {
// 		struct {
// 			sd_event_io_handler_t callback;
// 			int fd;
// 			uint32_t events;
// 			uint32_t revents;
// 			bool registered: 1;
// 		} io;
// 		struct {
// 			sd_event_time_handler_t callback;
// 			usec_t next, accuracy;
// 			unsigned earliest_index;
// 			unsigned latest_index;
// 		} time;
// 		struct {
// 			sd_event_signal_handler_t callback;
// 			struct signalfd_siginfo siginfo;
// 			int sig;
// 		} signal;
// 		struct {
// 			sd_event_child_handler_t callback;
// 			siginfo_t siginfo;
// 			pid_t pid;
// 			int options;
// 		} child;
// 		struct {
// 			sd_event_handler_t callback;
// 		} defer;
// 		struct {
// 			sd_event_handler_t callback;
// 		} post;
// 		struct {
// 			sd_event_handler_t callback;
// 			unsigned prioq_index;
// 		} exit;
// 	};
// };

static bool EVENT_SOURCE_WATCH_PIDFD(sd_event_source *s) {
        /* Returns true if this is a PID event source and can be implemented by watching EPOLLIN */
        return s &&
                s->type == SOURCE_CHILD &&
                s->child.pidfd >= 0 &&
                s->child.options == WEXITED;
}

static bool event_source_is_online(sd_event_source *s) {
        assert(s);
        return s->enabled != SD_EVENT_OFF && !s->ratelimited;
}

static bool event_source_is_offline(sd_event_source *s) {
        assert(s);
        return s->enabled == SD_EVENT_OFF || s->ratelimited;
}

struct clock_data {
	WakeupType wakeup;
	int fd;

	/* For all clocks we maintain two priority queues each, one
         * ordered for the earliest times the events may be
         * dispatched, and one ordered by the latest times they must
         * have been dispatched. The range between the top entries in
         * the two prioqs is the time window we can freely schedule
         * wakeups in */

	Prioq *earliest;
	Prioq *latest;
	usec_t next;

	bool needs_rearm: 1;
};

// struct sd_event {
// 	unsigned n_ref;

// 	int epoll_fd;
// 	int signal_fd;
// 	int watchdog_fd;

// 	Prioq *pending;
// 	Prioq *prepare;

// 	/* timerfd_create() only supports these five clocks so far. We
//          * can add support for more clocks when the kernel learns to
//          * deal with them, too. */
// 	struct clock_data realtime;
// 	struct clock_data boottime;
// 	struct clock_data monotonic;
// 	struct clock_data realtime_alarm;
// 	struct clock_data boottime_alarm;

// 	usec_t perturb;

// 	sigset_t sigset;
// 	sd_event_source **signal_sources;

// 	Hashmap *child_sources;
// 	unsigned n_enabled_child_sources;

// 	Set *post_sources;

// 	Prioq *exit;

// 	pid_t original_pid;

// 	uint64_t iteration;
// 	dual_timestamp timestamp;
// 	usec_t timestamp_boottime;
// 	int state;

// 	bool exit_requested: 1;
// 	bool need_process_child: 1;
// 	bool watchdog: 1;

// 	int exit_code;

// 	pid_t tid;
// 	sd_event **default_event_ptr;

// 	usec_t watchdog_last, watchdog_period;

// 	unsigned n_sources;

// 	LIST_HEAD(sd_event_source, sources);
// };

struct sd_event {
        unsigned n_ref;

        int epoll_fd;
        int watchdog_fd;

        Prioq *pending;
        Prioq *prepare;

        /* timerfd_create() only supports these five clocks so far. We
         * can add support for more clocks when the kernel learns to
         * deal with them, too. */
        struct clock_data realtime;
        struct clock_data boottime;
        struct clock_data monotonic;
        struct clock_data realtime_alarm;
        struct clock_data boottime_alarm;

        usec_t perturb;

        sd_event_source **signal_sources; /* indexed by signal number */
        Hashmap *signal_data; /* indexed by priority */

        Hashmap *child_sources;
        unsigned n_online_child_sources;

        Set *post_sources;

        Prioq *exit;

        Hashmap *inotify_data; /* indexed by priority */

        /* A list of inode structures that still have an fd open, that we need to close before the next loop iteration */
        LIST_HEAD(struct inode_data, inode_data_to_close_list);

        /* A list of inotify objects that already have events buffered which aren't processed yet */
        LIST_HEAD(struct inotify_data, buffered_inotify_data_list);

        /* A list of memory pressure event sources that still need their subscription string written */
        LIST_HEAD(sd_event_source, memory_pressure_write_list);

        uint64_t origin_id;

        uint64_t iteration;
        triple_timestamp timestamp;
        int state;

        bool exit_requested:1;
        bool need_process_child:1;
        bool watchdog:1;
        bool profile_delays:1;

        int exit_code;

        pid_t tid;
        sd_event **default_event_ptr;

        usec_t watchdog_last, watchdog_period;

        unsigned n_sources;

        struct epoll_event *event_queue;

        LIST_HEAD(sd_event_source, sources);

        sd_event_source *sigint_event_source, *sigterm_event_source;

        usec_t last_run_usec, last_log_usec;
        unsigned delays[sizeof(usec_t) * 8];
};

DEFINE_PRIVATE_ORIGIN_ID_HELPERS(sd_event, event);

struct signal_data {
        WakeupType wakeup;

        /* For each priority we maintain one signal fd, so that we
         * only have to dequeue a single event per priority at a
         * time. */

        int fd;
        int64_t priority;
        sigset_t sigset;
        sd_event_source *current;
};

/* A structure listing all event sources currently watching a specific inode */
struct inode_data {
        /* The identifier for the inode, the combination of the .st_dev + .st_ino fields of the file */
        ino_t ino;
        dev_t dev;

        /* An fd of the inode to watch. The fd is kept open until the next iteration of the loop, so that we can
         * rearrange the priority still until then, as we need the original inode to change the priority as we need to
         * add a watch descriptor to the right inotify for the priority which we can only do if we have a handle to the
         * original inode. We keep a list of all inode_data objects with an open fd in the to_close list (see below) of
         * the sd-event object, so that it is efficient to close everything, before entering the next event loop
         * iteration. */
        int fd;

        /* The path that the fd points to. The field is optional. */
        char *path;

        /* The inotify "watch descriptor" */
        int wd;

        /* The combination of the mask of all inotify watches on this inode we manage. This is also the mask that has
         * most recently been set on the watch descriptor. */
        uint32_t combined_mask;

        /* All event sources subscribed to this inode */
        LIST_HEAD(sd_event_source, event_sources);

        /* The inotify object we watch this inode with */
        struct inotify_data *inotify_data;

        /* A linked list of all inode data objects with fds to close (see above) */
        LIST_FIELDS(struct inode_data, to_close);
};

/* A structure encapsulating an inotify fd */
struct inotify_data {
        WakeupType wakeup;

        /* For each priority we maintain one inotify fd, so that we only have to dequeue a single event per priority at
         * a time */

        int fd;
        int64_t priority;

        Hashmap *inodes; /* The inode_data structures keyed by dev+ino */
        Hashmap *wd;     /* The inode_data structures keyed by the watch descriptor for each */

        /* The buffer we read inotify events into */
        union inotify_event_buffer buffer;
        size_t buffer_filled; /* fill level of the buffer */

        /* How many event sources are currently marked pending for this inotify. We won't read new events off the
         * inotify fd as long as there are still pending events on the inotify (because we have no strategy of queuing
         * the events locally if they can't be coalesced). */
        unsigned n_pending;

        /* If this counter is non-zero, don't GC the inotify data object even if not used to watch any inode
         * anymore. This is useful to pin the object for a bit longer, after the last event source needing it
         * is gone. */
        unsigned n_busy;

        /* A linked list of all inotify objects with data already read, that still need processing. We keep this list
         * to make it efficient to figure out what inotify objects to process data on next. */
        LIST_FIELDS(struct inotify_data, buffered);
};

static thread_local sd_event *default_event = NULL;

static void source_disconnect(sd_event_source *s);
static void event_gc_inode_data(sd_event *e, struct inode_data *d);

static sd_event *event_resolve(sd_event *e) {
        return e == SD_EVENT_DEFAULT ? default_event : e;
}

static int
pending_prioq_compare(const void *a, const void *b)
{
	const sd_event_source *x = a, *y = b;

	assert(x->pending);
	assert(y->pending);

	/* Enabled ones first */
	if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
		return -1;
	if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
		return 1;

	/* Lower priority values first */
	if (x->priority < y->priority)
		return -1;
	if (x->priority > y->priority)
		return 1;

	/* Older entries first */
	if (x->pending_iteration < y->pending_iteration)
		return -1;
	if (x->pending_iteration > y->pending_iteration)
		return 1;

	/* Stability for the rest */
	if (x < y)
		return -1;
	if (x > y)
		return 1;

	return 0;
}

static int
prepare_prioq_compare(const void *a, const void *b)
{
	const sd_event_source *x = a, *y = b;

	assert(x->prepare);
	assert(y->prepare);

	/* Enabled ones first */
	if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
		return -1;
	if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
		return 1;

	/* Move most recently prepared ones last, so that we can stop
         * preparing as soon as we hit one that has already been
         * prepared in the current iteration */
	if (x->prepare_iteration < y->prepare_iteration)
		return -1;
	if (x->prepare_iteration > y->prepare_iteration)
		return 1;

	/* Lower priority values first */
	if (x->priority < y->priority)
		return -1;
	if (x->priority > y->priority)
		return 1;

	/* Stability for the rest */
	if (x < y)
		return -1;
	if (x > y)
		return 1;

	return 0;
}

static int
earliest_time_prioq_compare(const void *a, const void *b)
{
	const sd_event_source *x = a, *y = b;

	assert(EVENT_SOURCE_IS_TIME(x->type));
	assert(x->type == y->type);

	/* Enabled ones first */
	if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
		return -1;
	if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
		return 1;

	/* Move the pending ones to the end */
	if (!x->pending && y->pending)
		return -1;
	if (x->pending && !y->pending)
		return 1;

	/* Order by time */
	if (x->time.next < y->time.next)
		return -1;
	if (x->time.next > y->time.next)
		return 1;

	/* Stability for the rest */
	if (x < y)
		return -1;
	if (x > y)
		return 1;

	return 0;
}

static int
latest_time_prioq_compare(const void *a, const void *b)
{
	const sd_event_source *x = a, *y = b;

	assert(EVENT_SOURCE_IS_TIME(x->type));
	assert(x->type == y->type);

	/* Enabled ones first */
	if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
		return -1;
	if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
		return 1;

	/* Move the pending ones to the end */
	if (!x->pending && y->pending)
		return -1;
	if (x->pending && !y->pending)
		return 1;

	/* Order by time */
	if (x->time.next + x->time.accuracy < y->time.next + y->time.accuracy)
		return -1;
	if (x->time.next + x->time.accuracy > y->time.next + y->time.accuracy)
		return 1;

	/* Stability for the rest */
	if (x < y)
		return -1;
	if (x > y)
		return 1;

	return 0;
}

static int
exit_prioq_compare(const void *a, const void *b)
{
	const sd_event_source *x = a, *y = b;

	assert(x->type == SOURCE_EXIT);
	assert(y->type == SOURCE_EXIT);

	/* Enabled ones first */
	if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
		return -1;
	if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
		return 1;

	/* Lower priority values first */
	if (x->priority < y->priority)
		return -1;
	if (x->priority > y->priority)
		return 1;

	/* Stability for the rest */
	if (x < y)
		return -1;
	if (x > y)
		return 1;

	return 0;
}

static void
free_clock_data(struct clock_data *d)
{
	assert(d);

	safe_close(d->fd);
	prioq_free(d->earliest);
	prioq_free(d->latest);
}

static sd_event *event_free(sd_event *e) {
        sd_event_source *s;

        assert(e);

        e->sigterm_event_source = sd_event_source_unref(e->sigterm_event_source);
        e->sigint_event_source = sd_event_source_unref(e->sigint_event_source);

        while ((s = e->sources)) {
                assert(s->floating);
                source_disconnect(s);
                sd_event_source_unref(s);
        }

        assert(e->n_sources == 0);

        if (e->default_event_ptr)
                *(e->default_event_ptr) = NULL;

        safe_close(e->epoll_fd);
        safe_close(e->watchdog_fd);

        free_clock_data(&e->realtime);
        free_clock_data(&e->boottime);
        free_clock_data(&e->monotonic);
        free_clock_data(&e->realtime_alarm);
        free_clock_data(&e->boottime_alarm);

        prioq_free(e->pending);
        prioq_free(e->prepare);
        prioq_free(e->exit);

        free(e->signal_sources);
        hashmap_free(e->signal_data);

        hashmap_free(e->inotify_data);

        hashmap_free(e->child_sources);
        set_free(e->post_sources);

        free(e->event_queue);

        return mfree(e);
}

_public_ int sd_event_new(sd_event** ret) {
        sd_event *e;
        int r;

        assert_return(ret, -EINVAL);

        e = new(sd_event, 1);
        if (!e)
                return -ENOMEM;

        *e = (sd_event) {
                .n_ref = 1,
                .epoll_fd = -EBADF,
                .watchdog_fd = -EBADF,
                .realtime.wakeup = WAKEUP_CLOCK_DATA,
                .realtime.fd = -EBADF,
                .realtime.next = USEC_INFINITY,
                .boottime.wakeup = WAKEUP_CLOCK_DATA,
                .boottime.fd = -EBADF,
                .boottime.next = USEC_INFINITY,
                .monotonic.wakeup = WAKEUP_CLOCK_DATA,
                .monotonic.fd = -EBADF,
                .monotonic.next = USEC_INFINITY,
                .realtime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .realtime_alarm.fd = -EBADF,
                .realtime_alarm.next = USEC_INFINITY,
                .boottime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .boottime_alarm.fd = -EBADF,
                .boottime_alarm.next = USEC_INFINITY,
                .perturb = USEC_INFINITY,
                .origin_id = origin_id_query(),
        };

        r = prioq_ensure_allocated(&e->pending, pending_prioq_compare);
        if (r < 0)
                goto fail;

        e->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (e->epoll_fd < 0) {
                r = -errno;
                goto fail;
        }

        e->epoll_fd = fd_move_above_stdio(e->epoll_fd);

        if (secure_getenv("SD_EVENT_PROFILE_DELAYS")) {
                log_debug("Event loop profiling enabled. Logarithmic histogram of event loop iterations in the range 2^0 %s 2^63 us will be logged every 5s.",
                          special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                e->profile_delays = true;
        }

        *ret = e;
        return 0;

fail:
        event_free(e);
        return r;
}

/* Define manually so we can add the origin check */
_public_ sd_event *sd_event_ref(sd_event *e) {
        if (!e)
                return NULL;
        if (event_origin_changed(e))
                return NULL;

        e->n_ref++;

        return e;
}

_public_ sd_event* sd_event_unref(sd_event *e) {
        if (!e)
                return NULL;
        if (event_origin_changed(e))
                return NULL;

        assert(e->n_ref > 0);
        if (--e->n_ref > 0)
                return NULL;

        return event_free(e);
}

// static bool
// event_pid_changed(sd_event *e)
// {
// 	assert(e);

// 	/* We don't support people creating am event loop and keeping
//          * it around over a fork(). Let's complain. */

// 	return e->original_pid != getpid();
// }

#define PROTECT_EVENT(e)                                                \
        _unused_ _cleanup_(sd_event_unrefp) sd_event *_ref = sd_event_ref(e);

static void source_io_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_IO);

        if (event_origin_changed(s->event))
                return;

        if (!s->io.registered)
                return;

        if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->io.fd, NULL) < 0)
                log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                strna(s->description), event_source_type_to_string(s->type));

        s->io.registered = false;
}

static int source_io_register(
                sd_event_source *s,
                int enabled,
                uint32_t events) {

        assert(s);
        assert(s->type == SOURCE_IO);
        assert(enabled != SD_EVENT_OFF);

        struct epoll_event ev = {
                .events = events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
                .data.ptr = s,
        };

        if (epoll_ctl(s->event->epoll_fd,
                      s->io.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                      s->io.fd, &ev) < 0)
                return -errno;

        s->io.registered = true;

        return 0;
}

static void source_child_pidfd_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_CHILD);

        if (event_origin_changed(s->event))
                return;

        if (!s->child.registered)
                return;

        if (EVENT_SOURCE_WATCH_PIDFD(s))
                if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->child.pidfd, NULL) < 0)
                        log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                        strna(s->description), event_source_type_to_string(s->type));

        s->child.registered = false;
}

static int source_child_pidfd_register(sd_event_source *s, int enabled) {
        assert(s);
        assert(s->type == SOURCE_CHILD);
        assert(enabled != SD_EVENT_OFF);

        if (EVENT_SOURCE_WATCH_PIDFD(s)) {
                struct epoll_event ev = {
                        .events = EPOLLIN | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
                        .data.ptr = s,
                };

                if (epoll_ctl(s->event->epoll_fd,
                              s->child.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                              s->child.pidfd, &ev) < 0)
                        return -errno;
        }

        s->child.registered = true;
        return 0;
}

static void source_memory_pressure_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (event_origin_changed(s->event))
                return;

        if (!s->memory_pressure.registered)
                return;

        if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->memory_pressure.fd, NULL) < 0)
                log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                strna(s->description), event_source_type_to_string(s->type));

        s->memory_pressure.registered = false;
}

static int source_memory_pressure_register(sd_event_source *s, int enabled) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);
        assert(enabled != SD_EVENT_OFF);

        struct epoll_event ev = {
                .events = s->memory_pressure.write_buffer_size > 0 ? EPOLLOUT :
                          (s->memory_pressure.events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0)),
                .data.ptr = s,
        };

        if (epoll_ctl(s->event->epoll_fd,
                      s->memory_pressure.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                      s->memory_pressure.fd, &ev) < 0)
                return -errno;

        s->memory_pressure.registered = true;
        return 0;
}

static void source_memory_pressure_add_to_write_list(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (s->memory_pressure.in_write_list)
                return;

        LIST_PREPEND(memory_pressure.write_list, s->event->memory_pressure_write_list, s);
        s->memory_pressure.in_write_list = true;
}

static void source_memory_pressure_remove_from_write_list(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (!s->memory_pressure.in_write_list)
                return;

        LIST_REMOVE(memory_pressure.write_list, s->event->memory_pressure_write_list, s);
        s->memory_pressure.in_write_list = false;
}

static clockid_t
event_source_type_to_clock(EventSourceType t)
{
	switch (t) {
	case SOURCE_TIME_REALTIME:
		return CLOCK_REALTIME;

	case SOURCE_TIME_BOOTTIME:
		return CLOCK_BOOTTIME;

	case SOURCE_TIME_MONOTONIC:
		return CLOCK_MONOTONIC;

	case SOURCE_TIME_REALTIME_ALARM:
		return CLOCK_REALTIME_ALARM;

	case SOURCE_TIME_BOOTTIME_ALARM:
		return CLOCK_BOOTTIME_ALARM;

	default:
		return (clockid_t)-1;
	}
}

static EventSourceType
clock_to_event_source_type(clockid_t clock)
{
	switch (clock) {
	case CLOCK_REALTIME:
		return SOURCE_TIME_REALTIME;

	case CLOCK_MONOTONIC:
		return SOURCE_TIME_MONOTONIC;

#ifdef HAVE_CLOCK_BOOTTIME
	case CLOCK_BOOTTIME:
		return SOURCE_TIME_BOOTTIME;

	case CLOCK_REALTIME_ALARM:
		return SOURCE_TIME_REALTIME_ALARM;

	case CLOCK_BOOTTIME_ALARM:
		return SOURCE_TIME_BOOTTIME_ALARM;
#endif

	default:
		return _SOURCE_EVENT_SOURCE_TYPE_INVALID;
	}
}

static struct clock_data *
event_get_clock_data(sd_event *e, EventSourceType t)
{
	assert(e);

	switch (t) {
	case SOURCE_TIME_REALTIME:
		return &e->realtime;

	case SOURCE_TIME_BOOTTIME:
		return &e->boottime;

	case SOURCE_TIME_MONOTONIC:
		return &e->monotonic;

	case SOURCE_TIME_REALTIME_ALARM:
		return &e->realtime_alarm;

	case SOURCE_TIME_BOOTTIME_ALARM:
		return &e->boottime_alarm;

	default:
		return NULL;
	}
}

static void event_free_signal_data(sd_event *e, struct signal_data *d) {
        assert(e);

        if (!d)
                return;

        hashmap_remove(e->signal_data, &d->priority);
        safe_close(d->fd);
        free(d);
}

static int event_make_signal_data(
                sd_event *e,
                int sig,
                struct signal_data **ret) {

        struct signal_data *d;
        bool added = false;
        sigset_t ss_copy;
        int64_t priority;
        int r;

        assert(e);

        if (event_origin_changed(e))
                return -ECHILD;

        if (e->signal_sources && e->signal_sources[sig])
                priority = e->signal_sources[sig]->priority;
        else
                priority = SD_EVENT_PRIORITY_NORMAL;

        d = hashmap_get(e->signal_data, &priority);
        if (d) {
                if (sigismember(&d->sigset, sig) > 0) {
                        if (ret)
                                *ret = d;
                        return 0;
                }
        } else {
                d = new(struct signal_data, 1);
                if (!d)
                        return -ENOMEM;

                *d = (struct signal_data) {
                        .wakeup = WAKEUP_SIGNAL_DATA,
                        .fd = -EBADF,
                        .priority = priority,
                };

                r = hashmap_ensure_put(&e->signal_data, &uint64_hash_ops, &d->priority, d);
                if (r < 0) {
                        free(d);
                        return r;
                }

                added = true;
        }

        ss_copy = d->sigset;
        assert_se(sigaddset(&ss_copy, sig) >= 0);

        r = signalfd(d->fd >= 0 ? d->fd : -1,   /* the first arg must be -1 or a valid signalfd */
                     &ss_copy,
                     SFD_NONBLOCK|SFD_CLOEXEC);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        d->sigset = ss_copy;

        if (d->fd >= 0) {
                if (ret)
                        *ret = d;
                return 0;
        }

        d->fd = fd_move_above_stdio(r);

        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, d->fd, &ev) < 0) {
                r = -errno;
                goto fail;
        }

        if (ret)
                *ret = d;

        return 0;

fail:
        if (added)
                event_free_signal_data(e, d);

        return r;
}

static void event_unmask_signal_data(sd_event *e, struct signal_data *d, int sig) {
        assert(e);
        assert(d);

        /* Turns off the specified signal in the signal data
         * object. If the signal mask of the object becomes empty that
         * way removes it. */

        if (sigismember(&d->sigset, sig) == 0)
                return;

        assert_se(sigdelset(&d->sigset, sig) >= 0);

        if (sigisemptyset(&d->sigset)) {
                /* If all the mask is all-zero we can get rid of the structure */
                event_free_signal_data(e, d);
                return;
        }

        if (event_origin_changed(e))
                return;

        assert(d->fd >= 0);

        if (signalfd(d->fd, &d->sigset, SFD_NONBLOCK|SFD_CLOEXEC) < 0)
                log_debug_errno(errno, "Failed to unset signal bit, ignoring: %m");
}

static void event_gc_signal_data(sd_event *e, const int64_t *priority, int sig) {
        struct signal_data *d;
        static const int64_t zero_priority = 0;

        assert(e);

        /* Rechecks if the specified signal is still something we are interested in. If not, we'll unmask it,
         * and possibly drop the signalfd for it. */

        if (sig == SIGCHLD &&
            e->n_online_child_sources > 0)
                return;

        if (e->signal_sources &&
            e->signal_sources[sig] &&
            event_source_is_online(e->signal_sources[sig]))
                return;

        /*
         * The specified signal might be enabled in three different queues:
         *
         * 1) the one that belongs to the priority passed (if it is non-NULL)
         * 2) the one that belongs to the priority of the event source of the signal (if there is one)
         * 3) the 0 priority (to cover the SIGCHLD case)
         *
         * Hence, let's remove it from all three here.
         */

        if (priority) {
                d = hashmap_get(e->signal_data, priority);
                if (d)
                        event_unmask_signal_data(e, d, sig);
        }

        if (e->signal_sources && e->signal_sources[sig]) {
                d = hashmap_get(e->signal_data, &e->signal_sources[sig]->priority);
                if (d)
                        event_unmask_signal_data(e, d, sig);
        }

        d = hashmap_get(e->signal_data, &zero_priority);
        if (d)
                event_unmask_signal_data(e, d, sig);
}

// static bool
// need_signal(sd_event *e, int signal)
// {
// 	return (e->signal_sources && e->signal_sources[signal] &&
// 		       e->signal_sources[signal]->enabled != SD_EVENT_OFF) ||
// 		(signal == SIGCHLD && e->n_enabled_child_sources > 0);
// }

// static int
// event_update_signal_fd(sd_event *e)
// {
// 	struct epoll_event ev = {};
// 	bool add_to_epoll;
// 	int r;

// 	assert(e);

// 	add_to_epoll = e->signal_fd < 0;

// 	r = signalfd(e->signal_fd, &e->sigset, SFD_NONBLOCK | SFD_CLOEXEC);
// 	if (r < 0)
// 		return -errno;

// 	e->signal_fd = r;

// 	if (!add_to_epoll)
// 		return 0;

// 	ev.events = EPOLLIN;
// 	ev.data.ptr = INT_TO_PTR(SOURCE_SIGNAL);

// 	r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, e->signal_fd, &ev);
// 	if (r < 0) {
// 		e->signal_fd = safe_close(e->signal_fd);
// 		return -errno;
// 	}

// 	return 0;
// }

static void event_source_time_prioq_reshuffle(sd_event_source *s) {
        struct clock_data *d;

        assert(s);

        /* Called whenever the event source's timer ordering properties changed, i.e. time, accuracy,
         * pending, enable state, and ratelimiting state. Makes sure the two prioq's are ordered
         * properly again. */

        if (s->ratelimited)
                d = &s->event->monotonic;
        else if (EVENT_SOURCE_IS_TIME(s->type))
                assert_se(d = event_get_clock_data(s->event, s->type));
        else
                return; /* no-op for an event source which is neither a timer nor ratelimited. */

        prioq_reshuffle(d->earliest, s, &s->earliest_index);
        prioq_reshuffle(d->latest, s, &s->latest_index);
        d->needs_rearm = true;
}

static void event_source_time_prioq_remove(
                sd_event_source *s,
                struct clock_data *d) {

        assert(s);
        assert(d);

        prioq_remove(d->earliest, s, &s->earliest_index);
        prioq_remove(d->latest, s, &s->latest_index);
        s->earliest_index = s->latest_index = PRIOQ_IDX_NULL;
        d->needs_rearm = true;
}

static void source_disconnect(sd_event_source *s) {
        sd_event *event;
        int r;

        assert(s);

        if (!s->event)
                return;

        assert(s->event->n_sources > 0);

        switch (s->type) {

        case SOURCE_IO:
                if (s->io.fd >= 0)
                        source_io_unregister(s);

                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
                /* Only remove this event source from the time event source here if it is not ratelimited. If
                 * it is ratelimited, we'll remove it below, separately. Why? Because the clock used might
                 * differ: ratelimiting always uses CLOCK_MONOTONIC, but timer events might use any clock */

                if (!s->ratelimited) {
                        struct clock_data *d;
                        assert_se(d = event_get_clock_data(s->event, s->type));
                        event_source_time_prioq_remove(s, d);
                }

                break;

        case SOURCE_SIGNAL:
                if (s->signal.sig > 0) {

                        if (s->event->signal_sources)
                                s->event->signal_sources[s->signal.sig] = NULL;

                        event_gc_signal_data(s->event, &s->priority, s->signal.sig);

                        if (s->signal.unblock) {
                                sigset_t new_ss;

                                if (sigemptyset(&new_ss) < 0)
                                        log_debug_errno(errno, "Failed to reset signal set, ignoring: %m");
                                else if (sigaddset(&new_ss, s->signal.sig) < 0)
                                        log_debug_errno(errno, "Failed to add signal %i to signal mask, ignoring: %m", s->signal.sig);
                                else {
                                        r = pthread_sigmask(SIG_UNBLOCK, &new_ss, NULL);
                                        if (r != 0)
                                                log_debug_errno(r, "Failed to unblock signal %i, ignoring: %m", s->signal.sig);
                                }
                        }
                }

                break;

        case SOURCE_CHILD:
                if (event_origin_changed(s->event))
                        s->child.process_owned = false;

                if (s->child.pid > 0) {
                        if (event_source_is_online(s)) {
                                assert(s->event->n_online_child_sources > 0);
                                s->event->n_online_child_sources--;
                        }

                        (void) hashmap_remove(s->event->child_sources, PID_TO_PTR(s->child.pid));
                }

                if (EVENT_SOURCE_WATCH_PIDFD(s))
                        source_child_pidfd_unregister(s);
                else
                        event_gc_signal_data(s->event, &s->priority, SIGCHLD);

                break;

        case SOURCE_DEFER:
                /* nothing */
                break;

        case SOURCE_POST:
                set_remove(s->event->post_sources, s);
                break;

        case SOURCE_EXIT:
                prioq_remove(s->event->exit, s, &s->exit.prioq_index);
                break;

        case SOURCE_INOTIFY: {
                struct inode_data *inode_data;

                inode_data = s->inotify.inode_data;
                if (inode_data) {
                        struct inotify_data *inotify_data;
                        assert_se(inotify_data = inode_data->inotify_data);

                        /* Detach this event source from the inode object */
                        LIST_REMOVE(inotify.by_inode_data, inode_data->event_sources, s);
                        s->inotify.inode_data = NULL;

                        if (s->pending) {
                                assert(inotify_data->n_pending > 0);
                                inotify_data->n_pending--;
                        }

                        /* Note that we don't reduce the inotify mask for the watch descriptor here if the inode is
                         * continued to being watched. That's because inotify doesn't really have an API for that: we
                         * can only change watch masks with access to the original inode either by fd or by path. But
                         * paths aren't stable, and keeping an O_PATH fd open all the time would mean wasting an fd
                         * continuously and keeping the mount busy which we can't really do. We could reconstruct the
                         * original inode from /proc/self/fdinfo/$INOTIFY_FD (as all watch descriptors are listed
                         * there), but given the need for open_by_handle_at() which is privileged and not universally
                         * available this would be quite an incomplete solution. Hence we go the other way, leave the
                         * mask set, even if it is not minimized now, and ignore all events we aren't interested in
                         * anymore after reception. Yes, this sucks, but … Linux … */

                        /* Maybe release the inode data (and its inotify) */
                        event_gc_inode_data(s->event, inode_data);
                }

                break;
        }

        case SOURCE_MEMORY_PRESSURE:
                source_memory_pressure_remove_from_write_list(s);
                source_memory_pressure_unregister(s);
                break;

        default:
                assert_not_reached();
        }

        if (s->pending)
                prioq_remove(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_remove(s->event->prepare, s, &s->prepare_index);

        if (s->ratelimited)
                event_source_time_prioq_remove(s, &s->event->monotonic);

        event = TAKE_PTR(s->event);
        LIST_REMOVE(sources, event->sources, s);
        event->n_sources--;

        /* Note that we don't invalidate the type here, since we still need it in order to close the fd or
         * pidfd associated with this event source, which we'll do only on source_free(). */

        if (!s->floating)
                sd_event_unref(event);
}

static sd_event_source* source_free(sd_event_source *s) {
        assert(s);

        source_disconnect(s);

        if (s->type == SOURCE_IO && s->io.owned)
                s->io.fd = safe_close(s->io.fd);

        if (s->type == SOURCE_CHILD) {
                /* Eventually the kernel will do this automatically for us, but for now let's emulate this (unreliably) in userspace. */

                if (s->child.process_owned) {

                        if (!s->child.exited) {
                                bool sent = false;

                                if (s->child.pidfd >= 0) {
                                        if (pidfd_send_signal(s->child.pidfd, SIGKILL, NULL, 0) < 0) {
                                                if (errno == ESRCH) /* Already dead */
                                                        sent = true;
                                                else if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                                        log_debug_errno(errno, "Failed to kill process " PID_FMT " via pidfd_send_signal(), re-trying via kill(): %m",
                                                                        s->child.pid);
                                        } else
                                                sent = true;
                                }

                                if (!sent)
                                        if (kill(s->child.pid, SIGKILL) < 0)
                                                if (errno != ESRCH) /* Already dead */
                                                        log_debug_errno(errno, "Failed to kill process " PID_FMT " via kill(), ignoring: %m",
                                                                        s->child.pid);
                        }

                        if (!s->child.waited) {
                                siginfo_t si = {};

                                /* Reap the child if we can */
                                (void) waitid(P_PID, s->child.pid, &si, WEXITED);
                        }
                }

                if (s->child.pidfd_owned)
                        s->child.pidfd = safe_close(s->child.pidfd);
        }

        if (s->type == SOURCE_MEMORY_PRESSURE) {
                s->memory_pressure.fd = safe_close(s->memory_pressure.fd);
                s->memory_pressure.write_buffer = mfree(s->memory_pressure.write_buffer);
        }

        if (s->destroy_callback)
                s->destroy_callback(s->userdata);

        free(s->description);
        return mfree(s);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_event_source*, source_free);

static int source_set_pending(sd_event_source *s, bool b) {
        int r;

        assert(s);
        assert(s->type != SOURCE_EXIT);

        if (s->pending == b)
                return 0;

        s->pending = b;

        if (b) {
                s->pending_iteration = s->event->iteration;

                r = prioq_put(s->event->pending, s, &s->pending_index);
                if (r < 0) {
                        s->pending = false;
                        return r;
                }
        } else
                assert_se(prioq_remove(s->event->pending, s, &s->pending_index));

        if (EVENT_SOURCE_IS_TIME(s->type))
                event_source_time_prioq_reshuffle(s);

        if (s->type == SOURCE_SIGNAL && !b) {
                struct signal_data *d;

                d = hashmap_get(s->event->signal_data, &s->priority);
                if (d && d->current == s)
                        d->current = NULL;
        }

        if (s->type == SOURCE_INOTIFY) {

                assert(s->inotify.inode_data);
                assert(s->inotify.inode_data->inotify_data);

                if (b)
                        s->inotify.inode_data->inotify_data->n_pending++;
                else {
                        assert(s->inotify.inode_data->inotify_data->n_pending > 0);
                        s->inotify.inode_data->inotify_data->n_pending--;
                }
        }

        return 1;
}

static sd_event_source *
source_new(sd_event *e, bool floating, EventSourceType type)
{
	sd_event_source *s;

	assert(e);

	s = new0(sd_event_source, 1);
	if (!s)
		return NULL;

	s->n_ref = 1;
	s->event = e;
	s->floating = floating;
	s->type = type;
	s->pending_index = s->prepare_index = PRIOQ_IDX_NULL;

	if (!floating)
		sd_event_ref(e);

	LIST_PREPEND(sources, e->sources, s);
	e->n_sources++;

	return s;
}

_public_ int sd_event_add_io(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t events,
                sd_event_io_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(fd >= 0, -EBADF);
        assert_return(!(events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP|EPOLLET)), -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = io_exit_callback;

        s = source_new(e, !ret, SOURCE_IO);
        if (!s)
                return -ENOMEM;

        s->wakeup = WAKEUP_EVENT_SOURCE;
        s->io.fd = fd;
        s->io.events = events;
        s->io.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        r = source_io_register(s, s->enabled, events);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

static void
initialize_perturb(sd_event *e)
{
	sd_id128_t bootid = {};

	/* When we sleep for longer, we try to realign the wakeup to
           the same time wihtin each minute/second/250ms, so that
           events all across the system can be coalesced into a single
           CPU wakeup. However, let's take some system-specific
           randomness for this value, so that in a network of systems
           with synced clocks timer events are distributed a
           bit. Here, we calculate a perturbation usec offset from the
           boot ID. */

	if (_likely_(e->perturb != USEC_INFINITY))
		return;

	if (sd_id128_get_boot(&bootid) >= 0)
		e->perturb =
			(bootid.qwords[0] ^ bootid.qwords[1]) % USEC_PER_MINUTE;
}

static int
event_setup_timer_fd(sd_event *e, struct clock_data *d, clockid_t clock)
{
	struct epoll_event ev = {};
	int r, fd;

	assert(e);
	assert(d);

	if (_likely_(d->fd >= 0))
		return 0;

	fd = timerfd_create(clock, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0)
		return -errno;

	ev.events = EPOLLIN;
	ev.data.ptr = INT_TO_PTR(clock_to_event_source_type(clock));

	r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	if (r < 0) {
		safe_close(fd);
		return -errno;
	}

	d->fd = fd;
	return 0;
}

static int
time_exit_callback(sd_event_source *s, uint64_t usec, void *userdata)
{
	assert(s);

	return sd_event_exit(sd_event_source_get_event(s),
		PTR_TO_INT(userdata));
}

_public_ int
sd_event_add_time(sd_event *e, sd_event_source **ret, clockid_t clock,
	uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback,
	void *userdata)
{
	EventSourceType type;
	sd_event_source *s;
	struct clock_data *d;
	int r;

	assert_return(e, -EINVAL);
	assert_return(usec != (uint64_t)-1, -EINVAL);
	assert_return(accuracy != (uint64_t)-1, -EINVAL);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(e), -ECHILD);

	if (!callback)
		callback = time_exit_callback;

	type = clock_to_event_source_type(clock);
	assert_return(type >= 0, -ENOTSUP);

	d = event_get_clock_data(e, type);
	assert(d);

	if (!d->earliest) {
		d->earliest = prioq_new(earliest_time_prioq_compare);
		if (!d->earliest)
			return -ENOMEM;
	}

	if (!d->latest) {
		d->latest = prioq_new(latest_time_prioq_compare);
		if (!d->latest)
			return -ENOMEM;
	}

	if (d->fd < 0) {
		r = event_setup_timer_fd(e, d, clock);
		if (r < 0)
			return r;
	}

	s = source_new(e, !ret, type);
	if (!s)
		return -ENOMEM;

	s->time.next = usec;
	s->time.accuracy = accuracy == 0 ? DEFAULT_ACCURACY_USEC : accuracy;
	s->time.callback = callback;
	s->time.earliest_index = s->time.latest_index = PRIOQ_IDX_NULL;
	s->userdata = userdata;
	s->enabled = SD_EVENT_ONESHOT;

	d->needs_rearm = true;

	r = prioq_put(d->earliest, s, &s->time.earliest_index);
	if (r < 0)
		goto fail;

	r = prioq_put(d->latest, s, &s->time.latest_index);
	if (r < 0)
		goto fail;

	if (ret)
		*ret = s;

	return 0;

fail:
	source_free(s);
	return r;
}

_public_ int
sd_event_add_time_relative(sd_event *e, sd_event_source **ret, clockid_t clock,
	uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback,
	void *userdata)
{
	usec_t t;
	int r;

	/*
	 * Same as sd_event_add_time() but operates relative to the event loop's
	 * time of last iteration, and checks for overflow.
	 */

	r = sd_event_now(e, clock, &t);
	if (r < 0)
		return r;

	if (usec >= USEC_INFINITY - t)
		return -EOVERFLOW;

	return sd_event_add_time(e, ret, clock, t + usec, accuracy, callback,
		userdata);
}

static int
signal_exit_callback(sd_event_source *s, const struct signalfd_siginfo *si,
	void *userdata)
{
	assert(s);

	return sd_event_exit(sd_event_source_get_event(s),
		PTR_TO_INT(userdata));
}

_public_ int sd_event_add_signal(
                sd_event *e,
                sd_event_source **ret,
                int sig,
                sd_event_signal_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        struct signal_data *d;
        sigset_t new_ss;
        bool block_it;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        /* Let's make sure our special flag stays outside of the valid signal range */
        assert_cc(_NSIG < SD_EVENT_SIGNAL_PROCMASK);

        if (sig & SD_EVENT_SIGNAL_PROCMASK) {
                sig &= ~SD_EVENT_SIGNAL_PROCMASK;
                assert_return(SIGNAL_VALID(sig), -EINVAL);

                block_it = true;
        } else {
                assert_return(SIGNAL_VALID(sig), -EINVAL);

                r = signal_is_blocked(sig);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBUSY;

                block_it = false;
        }

        if (!callback)
                callback = signal_exit_callback;

        if (!e->signal_sources) {
                e->signal_sources = new0(sd_event_source*, _NSIG);
                if (!e->signal_sources)
                        return -ENOMEM;
        } else if (e->signal_sources[sig])
                return -EBUSY;

        s = source_new(e, !ret, SOURCE_SIGNAL);
        if (!s)
                return -ENOMEM;

        s->signal.sig = sig;
        s->signal.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        e->signal_sources[sig] = s;

        if (block_it) {
                sigset_t old_ss;

                if (sigemptyset(&new_ss) < 0)
                        return -errno;

                if (sigaddset(&new_ss, sig) < 0)
                        return -errno;

                r = pthread_sigmask(SIG_BLOCK, &new_ss, &old_ss);
                if (r != 0)
                        return -r;

                r = sigismember(&old_ss, sig);
                if (r < 0)
                        return -errno;

                s->signal.unblock = !r;
        } else
                s->signal.unblock = false;

        r = event_make_signal_data(e, sig, &d);
        if (r < 0) {
                if (s->signal.unblock)
                        (void) pthread_sigmask(SIG_UNBLOCK, &new_ss, NULL);

                return r;
        }

        /* Use the signal name as description for the event source by default */
        (void) sd_event_source_set_description(s, signal_to_string(sig));

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int
sd_event_add_child(sd_event *e, sd_event_source **ret, pid_t pid, int options,
	sd_event_child_handler_t callback, void *userdata)
{
	sd_event_source *s;
	int r;
	bool previous;

	assert_return(e, -EINVAL);
	assert_return(pid > 1, -EINVAL);
	assert_return(!(options & ~(WEXITED | WSTOPPED | WCONTINUED)), -EINVAL);
	assert_return(options != 0, -EINVAL);
	assert_return(callback, -EINVAL);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(e), -ECHILD);

	r = hashmap_ensure_allocated(&e->child_sources, NULL);
	if (r < 0)
		return r;

	if (hashmap_contains(e->child_sources, INT_TO_PTR(pid)))
		return -EBUSY;

	previous = need_signal(e, SIGCHLD);

	s = source_new(e, !ret, SOURCE_CHILD);
	if (!s)
		return -ENOMEM;

	s->child.pid = pid;
	s->child.options = options;
	s->child.callback = callback;
	s->userdata = userdata;
	s->enabled = SD_EVENT_ONESHOT;

	r = hashmap_put(e->child_sources, INT_TO_PTR(pid), s);
	if (r < 0) {
		source_free(s);
		return r;
	}

	e->n_enabled_child_sources++;

	if (!previous) {
		assert_se(sigaddset(&e->sigset, SIGCHLD) == 0);

		r = event_update_signal_fd(e);
		if (r < 0) {
			source_free(s);
			return r;
		}
	}

	e->need_process_child = true;

	if (ret)
		*ret = s;

	return 0;
}

_public_ int
sd_event_add_defer(sd_event *e, sd_event_source **ret,
	sd_event_handler_t callback, void *userdata)
{
	sd_event_source *s;
	int r;

	assert_return(e, -EINVAL);
	assert_return(callback, -EINVAL);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(e), -ECHILD);

	s = source_new(e, !ret, SOURCE_DEFER);
	if (!s)
		return -ENOMEM;

	s->defer.callback = callback;
	s->userdata = userdata;
	s->enabled = SD_EVENT_ONESHOT;

	r = source_set_pending(s, true);
	if (r < 0) {
		source_free(s);
		return r;
	}

	if (ret)
		*ret = s;

	return 0;
}

_public_ int
sd_event_add_post(sd_event *e, sd_event_source **ret,
	sd_event_handler_t callback, void *userdata)
{
	sd_event_source *s;
	int r;

	assert_return(e, -EINVAL);
	assert_return(callback, -EINVAL);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(e), -ECHILD);

	r = set_ensure_allocated(&e->post_sources, NULL);
	if (r < 0)
		return r;

	s = source_new(e, !ret, SOURCE_POST);
	if (!s)
		return -ENOMEM;

	s->post.callback = callback;
	s->userdata = userdata;
	s->enabled = SD_EVENT_ON;

	r = set_put(e->post_sources, s);
	if (r < 0) {
		source_free(s);
		return r;
	}

	if (ret)
		*ret = s;

	return 0;
}

_public_ int
sd_event_add_exit(sd_event *e, sd_event_source **ret,
	sd_event_handler_t callback, void *userdata)
{
	sd_event_source *s;
	int r;

	assert_return(e, -EINVAL);
	assert_return(callback, -EINVAL);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(e), -ECHILD);

	if (!e->exit) {
		e->exit = prioq_new(exit_prioq_compare);
		if (!e->exit)
			return -ENOMEM;
	}

	s = source_new(e, !ret, SOURCE_EXIT);
	if (!s)
		return -ENOMEM;

	s->exit.callback = callback;
	s->userdata = userdata;
	s->exit.prioq_index = PRIOQ_IDX_NULL;
	s->enabled = SD_EVENT_ONESHOT;

	r = prioq_put(s->event->exit, s, &s->exit.prioq_index);
	if (r < 0) {
		source_free(s);
		return r;
	}

	if (ret)
		*ret = s;

	return 0;
}

_public_ sd_event_source *
sd_event_source_ref(sd_event_source *s)
{
	assert_return(s, NULL);

	assert(s->n_ref >= 1);
	s->n_ref++;

	return s;
}

_public_ sd_event_source *
sd_event_source_unref(sd_event_source *s)
{
	if (!s)
		return NULL;

	assert(s->n_ref >= 1);
	s->n_ref--;

	if (s->n_ref <= 0) {
		/* Here's a special hack: when we are called from a
                 * dispatch handler we won't free the event source
                 * immediately, but we will detach the fd from the
                 * epoll. This way it is safe for the caller to unref
                 * the event source and immediately close the fd, but
                 * we still retain a valid event source object after
                 * the callback. */

		if (s->dispatching) {
			if (s->type == SOURCE_IO)
				source_io_unregister(s);

			source_disconnect(s);
		} else
			source_free(s);
	}

	return NULL;
}

static void event_free_inode_data(
                sd_event *e,
                struct inode_data *d) {

        assert(e);

        if (!d)
                return;

        assert(!d->event_sources);

        if (d->fd >= 0) {
                LIST_REMOVE(to_close, e->inode_data_to_close_list, d);
                safe_close(d->fd);
        }

        if (d->inotify_data) {

                if (d->wd >= 0) {
                        if (d->inotify_data->fd >= 0 && !event_origin_changed(e)) {
                                /* So here's a problem. At the time this runs the watch descriptor might already be
                                 * invalidated, because an IN_IGNORED event might be queued right the moment we enter
                                 * the syscall. Hence, whenever we get EINVAL, ignore it entirely, since it's a very
                                 * likely case to happen. */

                                if (inotify_rm_watch(d->inotify_data->fd, d->wd) < 0 && errno != EINVAL)
                                        log_debug_errno(errno, "Failed to remove watch descriptor %i from inotify, ignoring: %m", d->wd);
                        }

                        assert_se(hashmap_remove(d->inotify_data->wd, INT_TO_PTR(d->wd)) == d);
                }

                assert_se(hashmap_remove(d->inotify_data->inodes, d) == d);
        }

        free(d->path);
        free(d);
}

static void event_gc_inotify_data(
                sd_event *e,
                struct inotify_data *d) {

        assert(e);

        /* GCs the inotify data object if we don't need it anymore. That's the case if we don't want to watch
         * any inode with it anymore, which in turn happens if no event source of this priority is interested
         * in any inode any longer. That said, we maintain an extra busy counter: if non-zero we'll delay GC
         * (under the expectation that the GC is called again once the counter is decremented). */

        if (!d)
                return;

        if (!hashmap_isempty(d->inodes))
                return;

        if (d->n_busy > 0)
                return;

        event_free_inotify_data(e, d);
}

static void event_gc_inode_data(
                sd_event *e,
                struct inode_data *d) {

        struct inotify_data *inotify_data;

        assert(e);

        if (!d)
                return;

        if (d->event_sources)
                return;

        inotify_data = d->inotify_data;
        event_free_inode_data(e, d);

        event_gc_inotify_data(e, inotify_data);
}

_public_ int
sd_event_source_set_description(sd_event_source *s, const char *description)
{
	assert_return(s, -EINVAL);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	return free_and_strdup(&s->description, description);
}

_public_ int
sd_event_source_get_description(sd_event_source *s, const char **description)
{
	assert_return(s, -EINVAL);
	assert_return(description, -EINVAL);
	assert_return(s->description, -ENXIO);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*description = s->description;
	return 0;
}

_public_ sd_event *
sd_event_source_get_event(sd_event_source *s)
{
	assert_return(s, NULL);

	return s->event;
}

_public_ int
sd_event_source_get_pending(sd_event_source *s)
{
	assert_return(s, -EINVAL);
	assert_return(s->type != SOURCE_EXIT, -EDOM);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	return s->pending;
}

_public_ int
sd_event_source_get_io_fd(sd_event_source *s)
{
	assert_return(s, -EINVAL);
	assert_return(s->type == SOURCE_IO, -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	return s->io.fd;
}

_public_ int
sd_event_source_set_io_fd(sd_event_source *s, int fd)
{
	int r;

	assert_return(s, -EINVAL);
	assert_return(fd >= 0, -EINVAL);
	assert_return(s->type == SOURCE_IO, -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	if (s->io.fd == fd)
		return 0;

	if (s->enabled == SD_EVENT_OFF) {
		s->io.fd = fd;
		s->io.registered = false;
	} else {
		int saved_fd;

		saved_fd = s->io.fd;
		assert(s->io.registered);

		s->io.fd = fd;
		s->io.registered = false;

		r = source_io_register(s, s->enabled, s->io.events);
		if (r < 0) {
			s->io.fd = saved_fd;
			s->io.registered = true;
			return r;
		}

		epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, saved_fd, NULL);
	}

	return 0;
}

_public_ int
sd_event_source_get_io_events(sd_event_source *s, uint32_t *events)
{
	assert_return(s, -EINVAL);
	assert_return(events, -EINVAL);
	assert_return(s->type == SOURCE_IO, -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*events = s->io.events;
	return 0;
}

_public_ int
sd_event_source_set_io_events(sd_event_source *s, uint32_t events)
{
	int r;

	assert_return(s, -EINVAL);
	assert_return(s->type == SOURCE_IO, -EDOM);
	assert_return(!(events &
			      ~(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI |
				      EPOLLERR | EPOLLHUP | EPOLLET)),
		-EINVAL);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	/* edge-triggered updates are never skipped, so we can reset edges */
	if (s->io.events == events && !(events & EPOLLET))
		return 0;

	if (s->enabled != SD_EVENT_OFF) {
		r = source_io_register(s, s->enabled, events);
		if (r < 0)
			return r;
	}

	s->io.events = events;
	source_set_pending(s, false);

	return 0;
}

_public_ int
sd_event_source_get_io_revents(sd_event_source *s, uint32_t *revents)
{
	assert_return(s, -EINVAL);
	assert_return(revents, -EINVAL);
	assert_return(s->type == SOURCE_IO, -EDOM);
	assert_return(s->pending, -ENODATA);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*revents = s->io.revents;
	return 0;
}

_public_ int
sd_event_source_get_signal(sd_event_source *s)
{
	assert_return(s, -EINVAL);
	assert_return(s->type == SOURCE_SIGNAL, -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	return s->signal.sig;
}

_public_ int
sd_event_source_get_priority(sd_event_source *s, int64_t *priority)
{
	assert_return(s, -EINVAL);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	return s->priority;
}

_public_ int
sd_event_source_set_priority(sd_event_source *s, int64_t priority)
{
	assert_return(s, -EINVAL);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	if (s->priority == priority)
		return 0;

	s->priority = priority;

	if (s->pending)
		prioq_reshuffle(s->event->pending, s, &s->pending_index);

	if (s->prepare)
		prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

	if (s->type == SOURCE_EXIT)
		prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);

	return 0;
}

_public_ int
sd_event_source_get_enabled(sd_event_source *s, int *m)
{
	assert_return(s, -EINVAL);
	assert_return(m, -EINVAL);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*m = s->enabled;
	return 0;
}

_public_ int
sd_event_source_set_enabled(sd_event_source *s, int m)
{
	int r;

	assert_return(s, -EINVAL);
	assert_return(m == SD_EVENT_OFF || m == SD_EVENT_ON ||
			m == SD_EVENT_ONESHOT,
		-EINVAL);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	/* If we are dead anyway, we are fine with turning off
         * sources, but everything else needs to fail. */
	if (s->event->state == SD_EVENT_FINISHED)
		return m == SD_EVENT_OFF ? 0 : -ESTALE;

	if (s->enabled == m)
		return 0;

	if (m == SD_EVENT_OFF) {
		switch (s->type) {
		case SOURCE_IO:
			r = source_io_unregister(s);
			if (r < 0)
				return r;

			s->enabled = m;
			break;

		case SOURCE_TIME_REALTIME:
		case SOURCE_TIME_BOOTTIME:
		case SOURCE_TIME_MONOTONIC:
		case SOURCE_TIME_REALTIME_ALARM:
		case SOURCE_TIME_BOOTTIME_ALARM: {
			struct clock_data *d;

			s->enabled = m;
			d = event_get_clock_data(s->event, s->type);
			assert(d);

			prioq_reshuffle(d->earliest, s,
				&s->time.earliest_index);
			prioq_reshuffle(d->latest, s, &s->time.latest_index);
			d->needs_rearm = true;
			break;
		}

		case SOURCE_SIGNAL:
			assert(need_signal(s->event, s->signal.sig));

			s->enabled = m;

			if (!need_signal(s->event, s->signal.sig)) {
				assert_se(sigdelset(&s->event->sigset,
						  s->signal.sig) == 0);

				(void)event_update_signal_fd(s->event);
				/* If disabling failed, we might get a spurious event,
                                 * but otherwise nothing bad should happen. */
			}

			break;

		case SOURCE_CHILD:
			assert(need_signal(s->event, SIGCHLD));

			s->enabled = m;

			assert(s->event->n_enabled_child_sources > 0);
			s->event->n_enabled_child_sources--;

			if (!need_signal(s->event, SIGCHLD)) {
				assert_se(sigdelset(&s->event->sigset,
						  SIGCHLD) == 0);

				(void)event_update_signal_fd(s->event);
			}

			break;

		case SOURCE_EXIT:
			s->enabled = m;
			prioq_reshuffle(s->event->exit, s,
				&s->exit.prioq_index);
			break;

		case SOURCE_DEFER:
		case SOURCE_POST:
			s->enabled = m;
			break;

		default:
			assert_not_reached();
		}

	} else {
		switch (s->type) {
		case SOURCE_IO:
			r = source_io_register(s, m, s->io.events);
			if (r < 0)
				return r;

			s->enabled = m;
			break;

		case SOURCE_TIME_REALTIME:
		case SOURCE_TIME_BOOTTIME:
		case SOURCE_TIME_MONOTONIC:
		case SOURCE_TIME_REALTIME_ALARM:
		case SOURCE_TIME_BOOTTIME_ALARM: {
			struct clock_data *d;

			s->enabled = m;
			d = event_get_clock_data(s->event, s->type);
			assert(d);

			prioq_reshuffle(d->earliest, s,
				&s->time.earliest_index);
			prioq_reshuffle(d->latest, s, &s->time.latest_index);
			d->needs_rearm = true;
			break;
		}

		case SOURCE_SIGNAL:
			/* Check status before enabling. */
			if (!need_signal(s->event, s->signal.sig)) {
				assert_se(sigaddset(&s->event->sigset,
						  s->signal.sig) == 0);

				r = event_update_signal_fd(s->event);
				if (r < 0) {
					s->enabled = SD_EVENT_OFF;
					return r;
				}
			}

			s->enabled = m;
			break;

		case SOURCE_CHILD:
			/* Check status before enabling. */
			if (s->enabled == SD_EVENT_OFF) {
				if (!need_signal(s->event, SIGCHLD)) {
					assert_se(sigaddset(&s->event->sigset,
							  s->signal.sig) == 0);

					r = event_update_signal_fd(s->event);
					if (r < 0) {
						s->enabled = SD_EVENT_OFF;
						return r;
					}
				}

				s->event->n_enabled_child_sources++;
			}

			s->enabled = m;
			break;

		case SOURCE_EXIT:
			s->enabled = m;
			prioq_reshuffle(s->event->exit, s,
				&s->exit.prioq_index);
			break;

		case SOURCE_DEFER:
		case SOURCE_POST:
			s->enabled = m;
			break;

		default:
			assert_not_reached();
		}
	}

	if (s->pending)
		prioq_reshuffle(s->event->pending, s, &s->pending_index);

	if (s->prepare)
		prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

	return 0;
}

_public_ int
sd_event_source_get_time(sd_event_source *s, uint64_t *usec)
{
	assert_return(s, -EINVAL);
	assert_return(usec, -EINVAL);
	assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*usec = s->time.next;
	return 0;
}

_public_ int
sd_event_source_set_time(sd_event_source *s, uint64_t usec)
{
	struct clock_data *d;

	assert_return(s, -EINVAL);
	assert_return(usec != (uint64_t)-1, -EINVAL);
	assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	s->time.next = usec;

	source_set_pending(s, false);

	d = event_get_clock_data(s->event, s->type);
	assert(d);

	prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
	prioq_reshuffle(d->latest, s, &s->time.latest_index);
	d->needs_rearm = true;

	return 0;
}

_public_ int
sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec)
{
	assert_return(s, -EINVAL);
	assert_return(usec, -EINVAL);
	assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*usec = s->time.accuracy;
	return 0;
}

_public_ int
sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec)
{
	struct clock_data *d;

	assert_return(s, -EINVAL);
	assert_return(usec != (uint64_t)-1, -EINVAL);
	assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	if (usec == 0)
		usec = DEFAULT_ACCURACY_USEC;

	s->time.accuracy = usec;

	source_set_pending(s, false);

	d = event_get_clock_data(s->event, s->type);
	assert(d);

	prioq_reshuffle(d->latest, s, &s->time.latest_index);
	d->needs_rearm = true;

	return 0;
}

_public_ int
sd_event_source_get_time_clock(sd_event_source *s, clockid_t *clock)
{
	assert_return(s, -EINVAL);
	assert_return(clock, -EINVAL);
	assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*clock = event_source_type_to_clock(s->type);
	return 0;
}

_public_ int
sd_event_source_get_child_pid(sd_event_source *s, pid_t *pid)
{
	assert_return(s, -EINVAL);
	assert_return(pid, -EINVAL);
	assert_return(s->type == SOURCE_CHILD, -EDOM);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	*pid = s->child.pid;
	return 0;
}

_public_ int
sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback)
{
	int r;

	assert_return(s, -EINVAL);
	assert_return(s->type != SOURCE_EXIT, -EDOM);
	assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(!event_pid_changed(s->event), -ECHILD);

	if (s->prepare == callback)
		return 0;

	if (callback && s->prepare) {
		s->prepare = callback;
		return 0;
	}

	r = prioq_ensure_allocated(&s->event->prepare, prepare_prioq_compare);
	if (r < 0)
		return r;

	s->prepare = callback;

	if (callback) {
		r = prioq_put(s->event->prepare, s, &s->prepare_index);
		if (r < 0)
			return r;
	} else
		prioq_remove(s->event->prepare, s, &s->prepare_index);

	return 0;
}

_public_ void *
sd_event_source_get_userdata(sd_event_source *s)
{
	assert_return(s, NULL);

	return s->userdata;
}

_public_ void *
sd_event_source_set_userdata(sd_event_source *s, void *userdata)
{
	void *ret;

	assert_return(s, NULL);

	ret = s->userdata;
	s->userdata = userdata;

	return ret;
}

static usec_t
sleep_between(sd_event *e, usec_t a, usec_t b)
{
	usec_t c;
	assert(e);
	assert(a <= b);

	if (a <= 0)
		return 0;

	if (b <= a + 1)
		return a;

	initialize_perturb(e);

	/*
          Find a good time to wake up again between times a and b. We
          have two goals here:

          a) We want to wake up as seldom as possible, hence prefer
             later times over earlier times.

          b) But if we have to wake up, then let's make sure to
             dispatch as much as possible on the entire system.

          We implement this by waking up everywhere at the same time
          within any given minute if we can, synchronised via the
          perturbation value determined from the boot ID. If we can't,
          then we try to find the same spot in every 10s, then 1s and
          then 250ms step. Otherwise, we pick the last possible time
          to wake up.
        */

	c = (b / USEC_PER_MINUTE) * USEC_PER_MINUTE + e->perturb;
	if (c >= b) {
		if (_unlikely_(c < USEC_PER_MINUTE))
			return b;

		c -= USEC_PER_MINUTE;
	}

	if (c >= a)
		return c;

	c = (b / (USEC_PER_SEC * 10)) * (USEC_PER_SEC * 10) +
		(e->perturb % (USEC_PER_SEC * 10));
	if (c >= b) {
		if (_unlikely_(c < USEC_PER_SEC * 10))
			return b;

		c -= USEC_PER_SEC * 10;
	}

	if (c >= a)
		return c;

	c = (b / USEC_PER_SEC) * USEC_PER_SEC + (e->perturb % USEC_PER_SEC);
	if (c >= b) {
		if (_unlikely_(c < USEC_PER_SEC))
			return b;

		c -= USEC_PER_SEC;
	}

	if (c >= a)
		return c;

	c = (b / (USEC_PER_MSEC * 250)) * (USEC_PER_MSEC * 250) +
		(e->perturb % (USEC_PER_MSEC * 250));
	if (c >= b) {
		if (_unlikely_(c < USEC_PER_MSEC * 250))
			return b;

		c -= USEC_PER_MSEC * 250;
	}

	if (c >= a)
		return c;

	return b;
}

static int
event_arm_timer(sd_event *e, struct clock_data *d)
{
	struct itimerspec its = {};
	sd_event_source *a, *b;
	usec_t t;
	int r;

	assert(e);
	assert(d);

	if (!d->needs_rearm)
		return 0;
	else
		d->needs_rearm = false;

	a = prioq_peek(d->earliest);
	if (!a || a->enabled == SD_EVENT_OFF) {
		if (d->fd < 0)
			return 0;

		if (d->next == USEC_INFINITY)
			return 0;

		/* disarm */
		r = timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL);
		if (r < 0)
			return r;

		d->next = USEC_INFINITY;
		return 0;
	}

	b = prioq_peek(d->latest);
	assert_se(b && b->enabled != SD_EVENT_OFF);

	t = sleep_between(e, a->time.next, b->time.next + b->time.accuracy);
	if (d->next == t)
		return 0;

	assert_se(d->fd >= 0);

	if (t == 0) {
		/* We don' want to disarm here, just mean some time looooong ago. */
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 1;
	} else
		timespec_store(&its.it_value, t);

	r = timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL);
	if (r < 0)
		return -errno;

	d->next = t;
	return 0;
}

static int process_io(sd_event *e, sd_event_source *s, uint32_t revents) {
        assert(e);
        assert(s);
        assert(s->type == SOURCE_IO);

        /* If the event source was already pending, we just OR in the
         * new revents, otherwise we reset the value. The ORing is
         * necessary to handle EPOLLONESHOT events properly where
         * readability might happen independently of writability, and
         * we need to keep track of both */

        if (s->pending)
                s->io.revents |= revents;
        else
                s->io.revents = revents;

        return source_set_pending(s, true);
}

static int flush_timer(sd_event *e, int fd, uint32_t events, usec_t *next) {
        uint64_t x;
        ssize_t ss;

        assert(e);
        assert(fd >= 0);

        assert_return(events == EPOLLIN, -EIO);

        ss = read(fd, &x, sizeof(x));
        if (ss < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return -errno;
        }

        if (_unlikely_(ss != sizeof(x)))
                return -EIO;

        if (next)
                *next = USEC_INFINITY;

        return 0;
}

static int process_timer(
                sd_event *e,
                usec_t n,
                struct clock_data *d) {

        sd_event_source *s;
        bool callback_invoked = false;
        int r;

        assert(e);
        assert(d);

        for (;;) {
                s = prioq_peek(d->earliest);
                assert(!s || EVENT_SOURCE_USES_TIME_PRIOQ(s->type));

                if (!s || time_event_source_next(s) > n)
                        break;

                if (s->ratelimited) {
                        /* This is an event sources whose ratelimit window has ended. Let's turn it on
                         * again. */
                        assert(s->ratelimited);

                        r = event_source_leave_ratelimit(s, /* run_callback */ true);
                        if (r < 0)
                                return r;
                        else if (r == 1)
                                callback_invoked = true;

                        continue;
                }

                if (s->enabled == SD_EVENT_OFF || s->pending)
                        break;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;

                event_source_time_prioq_reshuffle(s);
        }

        return callback_invoked;
}

static int process_child(sd_event *e, int64_t threshold, int64_t *ret_min_priority) {
        int64_t min_priority = threshold;
        bool something_new = false;
        sd_event_source *s;
        int r;

        assert(e);
        assert(ret_min_priority);

        if (!e->need_process_child) {
                *ret_min_priority = min_priority;
                return 0;
        }

        e->need_process_child = false;

        /* So, this is ugly. We iteratively invoke waitid() with P_PID + WNOHANG for each PID we wait
         * for, instead of using P_ALL. This is because we only want to get child information of very
         * specific child processes, and not all of them. We might not have processed the SIGCHLD event
         * of a previous invocation and we don't want to maintain a unbounded *per-child* event queue,
         * hence we really don't want anything flushed out of the kernel's queue that we don't care
         * about. Since this is O(n) this means that if you have a lot of processes you probably want
         * to handle SIGCHLD yourself.
         *
         * We do not reap the children here (by using WNOWAIT), this is only done after the event
         * source is dispatched so that the callback still sees the process as a zombie. */

        HASHMAP_FOREACH(s, e->child_sources) {
                assert(s->type == SOURCE_CHILD);

                if (s->priority > threshold)
                        continue;

                if (s->pending)
                        continue;

                if (event_source_is_offline(s))
                        continue;

                if (s->child.exited)
                        continue;

                if (EVENT_SOURCE_WATCH_PIDFD(s))
                        /* There's a usable pidfd known for this event source? Then don't waitid() for
                         * it here */
                        continue;

                zero(s->child.siginfo);
                if (waitid(P_PID, s->child.pid, &s->child.siginfo,
                           WNOHANG | (s->child.options & WEXITED ? WNOWAIT : 0) | s->child.options) < 0)
                        return negative_errno();

                if (s->child.siginfo.si_pid != 0) {
                        bool zombie = IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED);

                        if (zombie)
                                s->child.exited = true;

                        if (!zombie && (s->child.options & WEXITED)) {
                                /* If the child isn't dead then let's immediately remove the state
                                 * change from the queue, since there's no benefit in leaving it
                                 * queued. */

                                assert(s->child.options & (WSTOPPED|WCONTINUED));
                                (void) waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|(s->child.options & (WSTOPPED|WCONTINUED)));
                        }

                        r = source_set_pending(s, true);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                something_new = true;
                                min_priority = MIN(min_priority, s->priority);
                        }
                }
        }

        *ret_min_priority = min_priority;
        return something_new;
}

static int process_pidfd(sd_event *e, sd_event_source *s, uint32_t revents) {
        assert(e);
        assert(s);
        assert(s->type == SOURCE_CHILD);

        if (s->pending)
                return 0;

        if (event_source_is_offline(s))
                return 0;

        if (!EVENT_SOURCE_WATCH_PIDFD(s))
                return 0;

        zero(s->child.siginfo);
        if (waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG | WNOWAIT | s->child.options) < 0)
                return -errno;

        if (s->child.siginfo.si_pid == 0)
                return 0;

        if (IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED))
                s->child.exited = true;

        return source_set_pending(s, true);
}

static int process_signal(sd_event *e, struct signal_data *d, uint32_t events, int64_t *min_priority) {
        int r;

        assert(e);
        assert(d);
        assert_return(events == EPOLLIN, -EIO);
        assert(min_priority);

        /* If there's a signal queued on this priority and SIGCHLD is on this priority too, then make
         * sure to recheck the children we watch. This is because we only ever dequeue the first signal
         * per priority, and if we dequeue one, and SIGCHLD might be enqueued later we wouldn't know,
         * but we might have higher priority children we care about hence we need to check that
         * explicitly. */

        if (sigismember(&d->sigset, SIGCHLD))
                e->need_process_child = true;

        /* If there's already an event source pending for this priority we don't read another */
        if (d->current)
                return 0;

        for (;;) {
                struct signalfd_siginfo si;
                ssize_t n;
                sd_event_source *s = NULL;

                n = read(d->fd, &si, sizeof(si));
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                return 0;

                        return -errno;
                }

                if (_unlikely_(n != sizeof(si)))
                        return -EIO;

                assert(SIGNAL_VALID(si.ssi_signo));

                if (e->signal_sources)
                        s = e->signal_sources[si.ssi_signo];
                if (!s)
                        continue;
                if (s->pending)
                        continue;

                s->signal.siginfo = si;
                d->current = s;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;
                if (r > 0 && *min_priority >= s->priority) {
                        *min_priority = s->priority;
                        return 1; /* an event source with smaller priority is queued. */
                }

                return 0;
        }
}

static int event_inotify_data_read(sd_event *e, struct inotify_data *d, uint32_t revents, int64_t threshold) {
        ssize_t n;

        assert(e);
        assert(d);

        assert_return(revents == EPOLLIN, -EIO);

        /* If there's already an event source pending for this priority, don't read another */
        if (d->n_pending > 0)
                return 0;

        /* Is the read buffer non-empty? If so, let's not read more */
        if (d->buffer_filled > 0)
                return 0;

        if (d->priority > threshold)
                return 0;

        n = read(d->fd, &d->buffer, sizeof(d->buffer));
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return -errno;
        }

        assert(n > 0);
        d->buffer_filled = (size_t) n;
        LIST_PREPEND(buffered, e->buffered_inotify_data_list, d);

        return 1;
}

static void event_inotify_data_drop(sd_event *e, struct inotify_data *d, size_t sz) {
        assert(e);
        assert(d);
        assert(sz <= d->buffer_filled);

        if (sz == 0)
                return;

        /* Move the rest to the buffer to the front, in order to get things properly aligned again */
        memmove(d->buffer.raw, d->buffer.raw + sz, d->buffer_filled - sz);
        d->buffer_filled -= sz;

        if (d->buffer_filled == 0)
                LIST_REMOVE(buffered, e->buffered_inotify_data_list, d);
}

static int event_inotify_data_process(sd_event *e, struct inotify_data *d) {
        int r;

        assert(e);
        assert(d);

        /* If there's already an event source pending for this priority, don't read another */
        if (d->n_pending > 0)
                return 0;

        while (d->buffer_filled > 0) {
                size_t sz;

                /* Let's validate that the event structures are complete */
                if (d->buffer_filled < offsetof(struct inotify_event, name))
                        return -EIO;

                sz = offsetof(struct inotify_event, name) + d->buffer.ev.len;
                if (d->buffer_filled < sz)
                        return -EIO;

                if (d->buffer.ev.mask & IN_Q_OVERFLOW) {
                        struct inode_data *inode_data;

                        /* The queue overran, let's pass this event to all event sources connected to this inotify
                         * object */

                        HASHMAP_FOREACH(inode_data, d->inodes)
                                LIST_FOREACH(inotify.by_inode_data, s, inode_data->event_sources) {

                                        if (event_source_is_offline(s))
                                                continue;

                                        r = source_set_pending(s, true);
                                        if (r < 0)
                                                return r;
                                }
                } else {
                        struct inode_data *inode_data;

                        /* Find the inode object for this watch descriptor. If IN_IGNORED is set we also remove it from
                         * our watch descriptor table. */
                        if (d->buffer.ev.mask & IN_IGNORED) {

                                inode_data = hashmap_remove(d->wd, INT_TO_PTR(d->buffer.ev.wd));
                                if (!inode_data) {
                                        event_inotify_data_drop(e, d, sz);
                                        continue;
                                }

                                /* The watch descriptor was removed by the kernel, let's drop it here too */
                                inode_data->wd = -1;
                        } else {
                                inode_data = hashmap_get(d->wd, INT_TO_PTR(d->buffer.ev.wd));
                                if (!inode_data) {
                                        event_inotify_data_drop(e, d, sz);
                                        continue;
                                }
                        }

                        /* Trigger all event sources that are interested in these events. Also trigger all event
                         * sources if IN_IGNORED or IN_UNMOUNT is set. */
                        LIST_FOREACH(inotify.by_inode_data, s, inode_data->event_sources) {

                                if (event_source_is_offline(s))
                                        continue;

                                if ((d->buffer.ev.mask & (IN_IGNORED|IN_UNMOUNT)) == 0 &&
                                    (s->inotify.mask & d->buffer.ev.mask & IN_ALL_EVENTS) == 0)
                                        continue;

                                r = source_set_pending(s, true);
                                if (r < 0)
                                        return r;
                        }
                }

                /* Something pending now? If so, let's finish, otherwise let's read more. */
                if (d->n_pending > 0)
                        return 1;
        }

        return 0;
}

static int process_inotify(sd_event *e) {
        int r, done = 0;

        assert(e);

        LIST_FOREACH(buffered, d, e->buffered_inotify_data_list) {
                r = event_inotify_data_process(e, d);
                if (r < 0)
                        return r;
                if (r > 0)
                        done++;
        }

        return done;
}

static int process_memory_pressure(sd_event_source *s, uint32_t revents) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (s->pending)
                s->memory_pressure.revents |= revents;
        else
                s->memory_pressure.revents = revents;

        return source_set_pending(s, true);
}

static int source_dispatch(sd_event_source *s) {
        EventSourceType saved_type;
        sd_event *saved_event;
        int r = 0;

        assert(s);
        assert(s->pending || s->type == SOURCE_EXIT);

        /* Save the event source type, here, so that we still know it after the event callback which might
         * invalidate the event. */
        saved_type = s->type;

        /* Similarly, store a reference to the event loop object, so that we can still access it after the
         * callback might have invalidated/disconnected the event source. */
        saved_event = s->event;
        PROTECT_EVENT(saved_event);

        /* Check if we hit the ratelimit for this event source, and if so, let's disable it. */
        assert(!s->ratelimited);
        if (!ratelimit_below(&s->rate_limit)) {
                r = event_source_enter_ratelimited(s);
                if (r < 0)
                        return r;

                return 1;
        }

        if (!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        if (s->type != SOURCE_POST) {
                sd_event_source *z;

                /* If we execute a non-post source, let's mark all post sources as pending. */

                SET_FOREACH(z, s->event->post_sources) {
                        if (event_source_is_offline(z))
                                continue;

                        r = source_set_pending(z, true);
                        if (r < 0)
                                return r;
                }
        }

        if (s->type == SOURCE_MEMORY_PRESSURE) {
                r = source_memory_pressure_initiate_dispatch(s);
                if (r == -EIO) /* handle EIO errors similar to callback errors */
                        goto finish;
                if (r < 0)
                        return r;
                if (r > 0) /* already handled */
                        return 1;
        }

        if (s->enabled == SD_EVENT_ONESHOT) {
                r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
                if (r < 0)
                        return r;
        }

        s->dispatching = true;

        switch (s->type) {

        case SOURCE_IO:
                r = s->io.callback(s, s->io.fd, s->io.revents, s->userdata);
                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
                r = s->time.callback(s, s->time.next, s->userdata);
                break;

        case SOURCE_SIGNAL:
                r = s->signal.callback(s, &s->signal.siginfo, s->userdata);
                break;

        case SOURCE_CHILD: {
                bool zombie;

                zombie = IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED);

                r = s->child.callback(s, &s->child.siginfo, s->userdata);

                /* Now, reap the PID for good. */
                if (zombie) {
                        (void) waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|WEXITED);
                        s->child.waited = true;
                }

                break;
        }

        case SOURCE_DEFER:
                r = s->defer.callback(s, s->userdata);
                break;

        case SOURCE_POST:
                r = s->post.callback(s, s->userdata);
                break;

        case SOURCE_EXIT:
                r = s->exit.callback(s, s->userdata);
                break;

        case SOURCE_INOTIFY: {
                struct sd_event *e = s->event;
                struct inotify_data *d;
                size_t sz;

                assert(s->inotify.inode_data);
                assert_se(d = s->inotify.inode_data->inotify_data);

                assert(d->buffer_filled >= offsetof(struct inotify_event, name));
                sz = offsetof(struct inotify_event, name) + d->buffer.ev.len;
                assert(d->buffer_filled >= sz);

                /* If the inotify callback destroys the event source then this likely means we don't need to
                 * watch the inode anymore, and thus also won't need the inotify object anymore. But if we'd
                 * free it immediately, then we couldn't drop the event from the inotify event queue without
                 * memory corruption anymore, as below. Hence, let's not free it immediately, but mark it
                 * "busy" with a counter (which will ensure it's not GC'ed away prematurely). Let's then
                 * explicitly GC it after we are done dropping the inotify event from the buffer. */
                d->n_busy++;
                r = s->inotify.callback(s, &d->buffer.ev, s->userdata);
                d->n_busy--;

                /* When no event is pending anymore on this inotify object, then let's drop the event from
                 * the inotify event queue buffer. */
                if (d->n_pending == 0)
                        event_inotify_data_drop(e, d, sz);

                /* Now we don't want to access 'd' anymore, it's OK to GC now. */
                event_gc_inotify_data(e, d);
                break;
        }

        case SOURCE_MEMORY_PRESSURE:
                r = s->memory_pressure.callback(s, s->userdata);
                break;

        case SOURCE_WATCHDOG:
        case _SOURCE_EVENT_SOURCE_TYPE_MAX:
        case _SOURCE_EVENT_SOURCE_TYPE_INVALID:
                assert_not_reached();
        }

        s->dispatching = false;

finish:
        if (r < 0) {
                log_debug_errno(r, "Event source %s (type %s) returned error, %s: %m",
                                strna(s->description),
                                event_source_type_to_string(saved_type),
                                s->exit_on_failure ? "exiting" : "disabling");

                if (s->exit_on_failure)
                        (void) sd_event_exit(saved_event, r);
        }

        if (s->n_ref == 0)
                source_free(s);
        else if (r < 0)
                assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);

        return 1;
}

static int
event_prepare(sd_event *e)
{
	int r;

	assert(e);

	for (;;) {
		sd_event_source *s;

		s = prioq_peek(e->prepare);
		if (!s || s->prepare_iteration == e->iteration ||
			s->enabled == SD_EVENT_OFF)
			break;

		s->prepare_iteration = e->iteration;
		r = prioq_reshuffle(e->prepare, s, &s->prepare_index);
		if (r < 0)
			return r;

		assert(s->prepare);

		s->dispatching = true;
		r = s->prepare(s, s->userdata);
		s->dispatching = false;

		if (r < 0) {
			if (s->description)
				log_debug_errno(r,
					"Prepare callback of event source '%s' returned error, disabling: %m",
					s->description);
			else
				log_debug_errno(r,
					"Prepare callback of event source %p returned error, disabling: %m",
					s);
		}

		if (s->n_ref == 0)
			source_free(s);
		else if (r < 0)
			sd_event_source_set_enabled(s, SD_EVENT_OFF);
	}

	return 0;
}

static int
dispatch_exit(sd_event *e)
{
	sd_event_source *p;
	int r;

	assert(e);

	p = prioq_peek(e->exit);
	if (!p || p->enabled == SD_EVENT_OFF) {
		e->state = SD_EVENT_FINISHED;
		return 0;
	}

	sd_event_ref(e);
	e->iteration++;
	e->state = SD_EVENT_EXITING;

	r = source_dispatch(p);

	e->state = SD_EVENT_INITIAL;
	sd_event_unref(e);

	return r;
}

static sd_event_source *
event_next_pending(sd_event *e)
{
	sd_event_source *p;

	assert(e);

	p = prioq_peek(e->pending);
	if (!p)
		return NULL;

	if (p->enabled == SD_EVENT_OFF)
		return NULL;

	return p;
}

static int
arm_watchdog(sd_event *e)
{
	struct itimerspec its = {};
	usec_t t;
	int r;

	assert(e);
	assert(e->watchdog_fd >= 0);

	t = sleep_between(e, e->watchdog_last + (e->watchdog_period / 2),
		e->watchdog_last + (e->watchdog_period * 3 / 4));

	timespec_store(&its.it_value, t);

	/* Make sure we never set the watchdog to 0, which tells the
         * kernel to disable it. */
	if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
		its.it_value.tv_nsec = 1;

	r = timerfd_settime(e->watchdog_fd, TFD_TIMER_ABSTIME, &its, NULL);
	if (r < 0)
		return -errno;

	return 0;
}

static int
process_watchdog(sd_event *e)
{
	assert(e);

	if (!e->watchdog)
		return 0;

	/* Don't notify watchdog too often */
	if (e->watchdog_last + e->watchdog_period / 4 > e->timestamp.monotonic)
		return 0;

	sd_notify(false, "WATCHDOG=1");
	e->watchdog_last = e->timestamp.monotonic;

	return arm_watchdog(e);
}

_public_ int
sd_event_prepare(sd_event *e)
{
	int r;

	assert_return(e, -EINVAL);
	assert_return(!event_pid_changed(e), -ECHILD);
	assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
	assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

	if (e->exit_requested)
		goto pending;

	e->iteration++;

	r = event_prepare(e);
	if (r < 0)
		return r;

	r = event_arm_timer(e, &e->realtime);
	if (r < 0)
		return r;

	r = event_arm_timer(e, &e->boottime);
	if (r < 0)
		return r;

	r = event_arm_timer(e, &e->monotonic);
	if (r < 0)
		return r;

	r = event_arm_timer(e, &e->realtime_alarm);
	if (r < 0)
		return r;

	r = event_arm_timer(e, &e->boottime_alarm);
	if (r < 0)
		return r;

	if (event_next_pending(e) || e->need_process_child)
		goto pending;

	e->state = SD_EVENT_ARMED;

	return 0;

pending:
	e->state = SD_EVENT_ARMED;
	r = sd_event_wait(e, 0);
	if (r == 0)
		e->state = SD_EVENT_ARMED;

	return r;
}

static int epoll_wait_usec(
                int fd,
                struct epoll_event *events,
                int maxevents,
                usec_t timeout) {

        int msec;
        /* A wrapper that uses epoll_pwait2() if available, and falls back to epoll_wait() if not. */

// HACK: Fall back to epoll_wait
#if 0
// #if HAVE_EPOLL_PWAIT2
        static bool epoll_pwait2_absent = false;
        int r;

        /* epoll_pwait2() was added to Linux 5.11 (2021-02-14) and to glibc in 2.35 (2022-02-03). In contrast
         * to other syscalls we don't bother with our own fallback syscall wrappers on old libcs, since this
         * is not that obvious to implement given the libc and kernel definitions differ in the last
         * argument. Moreover, the only reason to use it is the more accurate time-outs (which is not a
         * biggie), let's hence rely on glibc's definitions, and fallback to epoll_pwait() when that's
         * missing. */

        if (!epoll_pwait2_absent && timeout != USEC_INFINITY) {
                r = epoll_pwait2(fd,
                                 events,
                                 maxevents,
                                 TIMESPEC_STORE(timeout),
                                 NULL);
                if (r >= 0)
                        return r;
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                        return -errno; /* Only fallback to old epoll_wait() if the syscall is masked or not
                                        * supported. */

                epoll_pwait2_absent = true;
        }
#endif

        if (timeout == USEC_INFINITY)
                msec = -1;
        else {
                usec_t k;

                k = DIV_ROUND_UP(timeout, USEC_PER_MSEC);
                if (k >= INT_MAX)
                        msec = INT_MAX; /* Saturate */
                else
                        msec = (int) k;
        }

        return RET_NERRNO(epoll_wait(fd, events, maxevents, msec));
}

static int process_epoll(sd_event *e, usec_t timeout, int64_t threshold, int64_t *ret_min_priority) {
        size_t n_event_queue, m, n_event_max;
        int64_t min_priority = threshold;
        bool something_new = false;
        int r;

        assert(e);
        assert(ret_min_priority);

        n_event_queue = MAX(e->n_sources, 1u);
        if (!GREEDY_REALLOC(e->event_queue, n_event_queue))
                return -ENOMEM;

        n_event_max = MALLOC_ELEMENTSOF(e->event_queue);

        /* If we still have inotify data buffered, then query the other fds, but don't wait on it */
        if (e->buffered_inotify_data_list)
                timeout = 0;

        for (;;) {
                r = epoll_wait_usec(
                                e->epoll_fd,
                                e->event_queue,
                                n_event_max,
                                timeout);
                if (r < 0)
                        return r;

                m = (size_t) r;

                if (m < n_event_max)
                        break;

                if (n_event_max >= n_event_queue * 10)
                        break;

                if (!GREEDY_REALLOC(e->event_queue, n_event_max + n_event_queue))
                        return -ENOMEM;

                n_event_max = MALLOC_ELEMENTSOF(e->event_queue);
                timeout = 0;
        }

        /* Set timestamp only when this is called first time. */
        if (threshold == INT64_MAX)
                triple_timestamp_now(&e->timestamp);

        for (size_t i = 0; i < m; i++) {

                if (e->event_queue[i].data.ptr == INT_TO_PTR(SOURCE_WATCHDOG))
                        r = flush_timer(e, e->watchdog_fd, e->event_queue[i].events, NULL);
                else {
                        WakeupType *t = e->event_queue[i].data.ptr;

                        switch (*t) {

                        case WAKEUP_EVENT_SOURCE: {
                                sd_event_source *s = e->event_queue[i].data.ptr;

                                assert(s);

                                if (s->priority > threshold)
                                        continue;

                                min_priority = MIN(min_priority, s->priority);

                                switch (s->type) {

                                case SOURCE_IO:
                                        r = process_io(e, s, e->event_queue[i].events);
                                        break;

                                case SOURCE_CHILD:
                                        r = process_pidfd(e, s, e->event_queue[i].events);
                                        break;

                                case SOURCE_MEMORY_PRESSURE:
                                        r = process_memory_pressure(s, e->event_queue[i].events);
                                        break;

                                default:
                                        assert_not_reached();
                                }

                                break;
                        }

                        case WAKEUP_CLOCK_DATA: {
                                struct clock_data *d = e->event_queue[i].data.ptr;

                                assert(d);

                                r = flush_timer(e, d->fd, e->event_queue[i].events, &d->next);
                                break;
                        }

                        case WAKEUP_SIGNAL_DATA:
                                r = process_signal(e, e->event_queue[i].data.ptr, e->event_queue[i].events, &min_priority);
                                break;

                        case WAKEUP_INOTIFY_DATA:
                                r = event_inotify_data_read(e, e->event_queue[i].data.ptr, e->event_queue[i].events, threshold);
                                break;

                        default:
                                assert_not_reached();
                        }
                }
                if (r < 0)
                        return r;
                if (r > 0)
                        something_new = true;
        }

        *ret_min_priority = min_priority;
        return something_new;
}

_public_ int sd_event_wait(sd_event *e, uint64_t timeout) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_ARMED, -EBUSY);

        if (e->exit_requested) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        for (int64_t threshold = INT64_MAX; ; threshold--) {
                int64_t epoll_min_priority, child_min_priority;

                /* There may be a possibility that new epoll (especially IO) and child events are
                 * triggered just after process_epoll() call but before process_child(), and the new IO
                 * events may have higher priority than the child events. To salvage these events,
                 * let's call epoll_wait() again, but accepts only events with higher priority than the
                 * previous. See issue https://github.com/systemd/systemd/issues/18190 and comments
                 * https://github.com/systemd/systemd/pull/18750#issuecomment-785801085
                 * https://github.com/systemd/systemd/pull/18922#issuecomment-792825226 */

                r = process_epoll(e, timeout, threshold, &epoll_min_priority);
                if (r == -EINTR) {
                        e->state = SD_EVENT_PENDING;
                        return 1;
                }
                if (r < 0)
                        goto finish;
                if (r == 0 && threshold < INT64_MAX)
                        /* No new epoll event. */
                        break;

                r = process_child(e, threshold, &child_min_priority);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        /* No new child event. */
                        break;

                threshold = MIN(epoll_min_priority, child_min_priority);
                if (threshold == INT64_MIN)
                        break;

                timeout = 0;
        }

        r = process_watchdog(e);
        if (r < 0)
                goto finish;

        r = process_inotify(e);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.monotonic, &e->monotonic);
        if (r < 0)
                goto finish;
        else if (r == 1) {
                /* Ratelimit expiry callback was called. Let's postpone processing pending sources and
                 * put loop in the initial state in order to evaluate (in the next iteration) also sources
                 * there were potentially re-enabled by the callback.
                 *
                 * Wondering why we treat only this invocation of process_timer() differently? Once event
                 * source is ratelimited we essentially transform it into CLOCK_MONOTONIC timer hence
                 * ratelimit expiry callback is never called for any other timer type. */
                r = 0;
                goto finish;
        }

        if (event_next_pending(e)) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        r = 0;

finish:
        e->state = SD_EVENT_INITIAL;

        return r;
}

_public_ int sd_event_dispatch(sd_event *e) {
        sd_event_source *p;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_PENDING, -EBUSY);

        if (e->exit_requested)
                return dispatch_exit(e);

        p = event_next_pending(e);
        if (p) {
                PROTECT_EVENT(e);

                e->state = SD_EVENT_RUNNING;
                r = source_dispatch(p);
                e->state = SD_EVENT_INITIAL;
                return r;
        }

        e->state = SD_EVENT_INITIAL;

        return 1;
}

static void event_log_delays(sd_event *e) {
        char b[ELEMENTSOF(e->delays) * DECIMAL_STR_MAX(unsigned) + 1], *p;
        size_t l, i;

        p = b;
        l = sizeof(b);
        for (i = 0; i < ELEMENTSOF(e->delays); i++) {
                l = strpcpyf(&p, l, "%u ", e->delays[i]);
                e->delays[i] = 0;
        }
        log_debug("Event loop iterations: %s", b);
}

_public_ int sd_event_run(sd_event *e, uint64_t timeout) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        if (e->profile_delays && e->last_run_usec != 0) {
                usec_t this_run;
                unsigned l;

                this_run = now(CLOCK_MONOTONIC);

                l = log2u64(this_run - e->last_run_usec);
                assert(l < ELEMENTSOF(e->delays));
                e->delays[l]++;

                if (this_run - e->last_log_usec >= 5*USEC_PER_SEC) {
                        event_log_delays(e);
                        e->last_log_usec = this_run;
                }
        }

        /* Make sure that none of the preparation callbacks ends up freeing the event source under our feet */
        PROTECT_EVENT(e);

        r = sd_event_prepare(e);
        if (r == 0)
                /* There was nothing? Then wait... */
                r = sd_event_wait(e, timeout);

        if (e->profile_delays)
                e->last_run_usec = now(CLOCK_MONOTONIC);

        if (r > 0) {
                /* There's something now, then let's dispatch it */
                r = sd_event_dispatch(e);
                if (r < 0)
                        return r;

                return 1;
        }

        return r;
}

_public_ int sd_event_loop(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);


        PROTECT_EVENT(e);

        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, UINT64_MAX);
                if (r < 0)
                        return r;
        }

        return e->exit_code;
}

_public_ int sd_event_get_fd(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->epoll_fd;
}

_public_ int sd_event_get_state(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->state;
}

_public_ int sd_event_get_exit_code(sd_event *e, int *code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!e->exit_requested)
                return -ENODATA;

        if (code)
                *code = e->exit_code;
        return 0;
}

_public_ int sd_event_exit(sd_event *e, int code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        e->exit_requested = true;
        e->exit_code = code;

        return 0;
}

_public_ int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(usec, -EINVAL);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!TRIPLE_TIMESTAMP_HAS_CLOCK(clock))
                return -EOPNOTSUPP;

        if (!triple_timestamp_is_set(&e->timestamp)) {
                /* Implicitly fall back to now() if we never ran before and thus have no cached time. */
                *usec = now(clock);
                return 1;
        }

        *usec = triple_timestamp_by_clock(&e->timestamp, clock);
        return 0;
}

_public_ int sd_event_default(sd_event **ret) {
        sd_event *e = NULL;
        int r;

        if (!ret)
                return !!default_event;

        if (default_event) {
                *ret = sd_event_ref(default_event);
                return 0;
        }

        r = sd_event_new(&e);
        if (r < 0)
                return r;

        e->default_event_ptr = &default_event;
        e->tid = gettid();
        default_event = e;

        *ret = e;
        return 1;
}

_public_ int sd_event_get_tid(sd_event *e, pid_t *tid) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(tid, -EINVAL);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (e->tid != 0) {
                *tid = e->tid;
                return 0;
        }

        return -ENXIO;
}

_public_ int sd_event_set_watchdog(sd_event *e, int b) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (e->watchdog == !!b)
                return e->watchdog;

        if (b) {
                r = sd_watchdog_enabled(false, &e->watchdog_period);
                if (r <= 0)
                        return r;

                /* Issue first ping immediately */
                sd_notify(false, "WATCHDOG=1");
                e->watchdog_last = now(CLOCK_MONOTONIC);

                e->watchdog_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
                if (e->watchdog_fd < 0)
                        return -errno;

                r = arm_watchdog(e);
                if (r < 0)
                        goto fail;

                struct epoll_event ev = {
                        .events = EPOLLIN,
                        .data.ptr = INT_TO_PTR(SOURCE_WATCHDOG),
                };

                if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, e->watchdog_fd, &ev) < 0) {
                        r = -errno;
                        goto fail;
                }

        } else {
                if (e->watchdog_fd >= 0) {
                        (void) epoll_ctl(e->epoll_fd, EPOLL_CTL_DEL, e->watchdog_fd, NULL);
                        e->watchdog_fd = safe_close(e->watchdog_fd);
                }
        }

        e->watchdog = b;
        return e->watchdog;

fail:
        e->watchdog_fd = safe_close(e->watchdog_fd);
        return r;
}

_public_ int sd_event_get_watchdog(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->watchdog;
}

_public_ int sd_event_get_iteration(sd_event *e, uint64_t *ret) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        *ret = e->iteration;
        return 0;
}
