#ifndef SD_EVENT_H_
#define SD_EVENT_H_

#include <sys/types.h>
#include <sys/poll.h>
#include <inttypes.h>
#include <signal.h>

#include "_sd-common.h"
#include "svc-config.h"

#ifdef SVC_HAVE_epoll
#include <sys/epoll.h>
#else
#define EPOLLIN POLLIN
#define EPOLLPRI POLLPRI
#define EPOLLOUT POLLOUT
#define EPOLLERR POLLERR
#define EPOLLHUP POLLHUP
#ifdef POLLRDHUP
#define EPOLLRDHUP POLLRDHUP
#else
#define EPOLLRDHUP 0x8000 /* hopefully high enough! */
#endif
#endif

#include "bsdsigfd.h"

_SD_BEGIN_DECLARATIONS;

#define sd_evloop sd_event

typedef struct sd_evloop sd_evloop;
typedef struct sd_event_source sd_event_source;

typedef enum sd_event_source_enabled {
	SD_EVENT_OFF = 0,
	SD_EVENT_ON = 1,
	SD_EVENT_ONESHOT = -1
} sd_event_source_enabled_t;

/* The state of the event loop. */
typedef enum sd_event_loop_status {
	SD_EVENT_INITIAL, /* newly created */
	SD_EVENT_PREPARING, /* preparing an event source */
	SD_EVENT_ARMED, /* waited but no events ready yet */
	SD_EVENT_PENDING, /* waited and events are ready to dispatch */
	SD_EVENT_RUNNING, /* dispatching event source */
	SD_EVENT_EXITING, /* running exit callbacks */
	SD_EVENT_FINISHED, /* event loop exited */
} sd_event_loop_status_t;

enum {
	/* And everything in-between and outside is good too */
	SD_EVENT_PRIORITY_IMPORTANT = -100,
	SD_EVENT_PRIORITY_NORMAL = 0,
	SD_EVENT_PRIORITY_IDLE = 100
};

typedef int (*sd_event_handler_t)(sd_event_source *s, void *userdata);
typedef int (*sd_event_io_handler_t)(sd_event_source *s, int fd,
	uint32_t revents, void *userdata);
typedef int (*sd_event_time_handler_t)(sd_event_source *s, uint64_t usec,
	void *userdata);
typedef int (*sd_event_signal_handler_t)(sd_event_source *s,
	const struct sigfd_siginfo *si, void *userdata);
typedef int (*sd_event_child_handler_t)(sd_event_source *s, const siginfo_t *si,
	void *userdata);

int sd_event_default(sd_event **e);

int sd_event_new(sd_event **e);
sd_event *sd_event_ref(sd_event *e);
sd_event *sd_event_unref(sd_event *e);

int sd_event_add_io(sd_event *e, sd_event_source **s, int fd, uint32_t events,
	sd_event_io_handler_t callback, void *userdata);
int sd_event_add_time(sd_event *e, sd_event_source **s, clockid_t clock,
	uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback,
	void *userdata);
int sd_event_add_signal(sd_event *e, sd_event_source **s, int sig,
	sd_event_signal_handler_t callback, void *userdata);
int sd_event_add_child(sd_event *e, sd_event_source **s, pid_t pid, int options,
	sd_event_child_handler_t callback, void *userdata);
int sd_event_add_defer(sd_event *e, sd_event_source **s,
	sd_event_handler_t callback, void *userdata);
int sd_event_add_post(sd_event *e, sd_event_source **s,
	sd_event_handler_t callback, void *userdata);
int sd_event_add_exit(sd_event *e, sd_event_source **s,
	sd_event_handler_t callback, void *userdata);

/**
 * Prepare for a loop iteration and poll for events, returning immediately.
 *
 * \pre Loop in SD_EVENT_INITIAL state.
 *
 * @retval -errno an error occured.
 * @retval 0 no events were returned; loop now in SD_EVENT_ARMED state;
 * now call sd_event_wait().
 * @retval >0 events were returned; loop now in SD_EVENT_PENDING state; now call
 * sd_event_dispatch().
 */
int sd_event_prepare(sd_event *e);
/**
 * Wait up to \p timeout milliseconds for an event to be received.
 *
 * \pre Loop in SD_EVENT_ARMED state.
 *
 * @retval -errno an error occured.
 * @retval 0 no events were returned; loop now in SD_EVENT_INITIAL state; now
 * call sd_event_prepare().
 * @retval >0 events were returend; loop now in SD_EVENT_PENDING state; now call
 * sd_event_dispatch().
 */
int sd_event_wait(sd_event *e, uint64_t timeout);
/**
 * Dispatch pending loop events.
 *
 * \pre Loop in SD_EVENT_PENDING state.
 *
 * @retval -errno an error occured.
 * @retval 0 events or at least exit callbacks dispatched; loop now in
 * SD_EVENT_FINISHED state.
 * @retval >0 events were dispatched; loop now in SD_EVENT_INITIAL state.
 */
int sd_event_dispatch(sd_event *e);
/**
 * Run a single iteration of the event loop.
 *
 * @retval <0 an error occurred.
 * @retval 0 timeout elapsed before event dispatch.
 * @retval >0 at least one event source dispatched; state is now SD_EVENT_INITIAL
 */
int sd_event_run(sd_event *e, uint64_t timeout);
/**
 * Run the event loop.
 *
 * @retval <0 an error occurred.
 * @retval >= 0 loop finished; return code is the exit value of the loop.
 */
int sd_event_loop(sd_event *e);
/**
 * Request the event loop to exit with the given code.
 */
int sd_event_exit(sd_event *e, int code);

/**
 * Request the time at which the last iteration of the event loop started.
 */
int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec);

int sd_event_get_fd(sd_event *e);
int sd_event_get_state(sd_event *e);
int sd_event_get_tid(sd_event *e, pid_t *tid);
int sd_event_get_exit_code(sd_event *e, int *code);
int sd_event_set_watchdog(sd_event *e, int b);
int sd_event_get_watchdog(sd_event *e);
int sd_event_get_iteration(sd_event *e, uint64_t *ret);

sd_event_source *sd_event_source_ref(sd_event_source *s);
sd_event_source *sd_event_source_unref(sd_event_source *s);

sd_event *sd_event_source_get_event(sd_event_source *s);
void *sd_event_source_get_userdata(sd_event_source *s);
void *sd_event_source_set_userdata(sd_event_source *s, void *userdata);

int sd_event_source_set_description(sd_event_source *s,
	const char *description);
int sd_event_source_get_description(sd_event_source *s,
	const char **description);
int sd_event_source_set_prepare(sd_event_source *s,
	sd_event_handler_t callback);
int sd_event_source_get_pending(sd_event_source *s);
int sd_event_source_get_priority(sd_event_source *s, int64_t *priority);
int sd_event_source_set_priority(sd_event_source *s, int64_t priority);
int sd_event_source_get_enabled(sd_event_source *s, int *enabled);
int sd_event_source_set_enabled(sd_event_source *s, int enabled);
int sd_event_source_get_io_fd(sd_event_source *s);
int sd_event_source_set_io_fd(sd_event_source *s, int fd);
int sd_event_source_get_io_events(sd_event_source *s, uint32_t *events);
int sd_event_source_set_io_events(sd_event_source *s, uint32_t events);
int sd_event_source_get_io_revents(sd_event_source *s, uint32_t *revents);
int sd_event_source_get_time(sd_event_source *s, uint64_t *usec);
int sd_event_source_set_time(sd_event_source *s, uint64_t usec);
int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec);
int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec);
int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *clock);
int sd_event_source_get_signal(sd_event_source *s);
int sd_event_source_get_child_pid(sd_event_source *s, pid_t *pid);

_SD_END_DECLARATIONS;

#endif /* SD_EVENT_H_ */
