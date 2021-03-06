/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-stream.h"
#include "journald-syslog.h"
#include "socket-util.h"

#define STDOUT_STREAMS_MAX 4096

typedef enum StdoutStreamState {
	STDOUT_STREAM_IDENTIFIER,
	STDOUT_STREAM_UNIT_ID,
	STDOUT_STREAM_PRIORITY,
	STDOUT_STREAM_LEVEL_PREFIX,
	STDOUT_STREAM_FORWARD_TO_SYSLOG,
	STDOUT_STREAM_FORWARD_TO_KMSG,
	STDOUT_STREAM_FORWARD_TO_CONSOLE,
	STDOUT_STREAM_RUNNING
} StdoutStreamState;

struct StdoutStream {
	Server *server;
	StdoutStreamState state;

	ev_io watch;

	struct socket_ucred ucred;
#ifdef HAVE_SELINUX
	security_context_t security_context;
#endif

	char *identifier;
	char *unit_id;
	int priority;
	bool level_prefix : 1;
	bool forward_to_syslog : 1;
	bool forward_to_kmsg : 1;
	bool forward_to_console : 1;

	char buffer[LINE_MAX + 1];
	size_t length;

	IWLIST_FIELDS(StdoutStream, stdout_stream);
};

static int stdout_stream_log(StdoutStream *s, const char *p)
{
	struct iovec iovec[N_IOVEC_META_FIELDS + 5];
	int priority;
	char syslog_priority[] = "PRIORITY=\0";
	char syslog_facility[sizeof("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(priority)];
	_cleanup_free_ char *message = NULL, *syslog_identifier = NULL;
	unsigned n = 0;
	char *label = NULL;
	size_t label_len = 0;

	assert(s);
	assert(p);

	if (isempty(p))
		return 0;

	priority = s->priority;

	if (s->level_prefix)
		syslog_parse_priority(&p, &priority, false);

	if (s->forward_to_syslog || s->server->forward_to_syslog)
		server_forward_syslog(s->server, syslog_fixup_facility(priority), s->identifier, p,
		    &s->ucred, NULL);

	if (s->forward_to_kmsg || s->server->forward_to_kmsg)
		server_forward_kmsg(s->server, priority, s->identifier, p, &s->ucred);

	if (s->forward_to_console || s->server->forward_to_console)
		server_forward_console(s->server, priority, s->identifier, p, &s->ucred);

	IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=stdout");

	syslog_priority[strlen("PRIORITY=")] = '0' + LOG_PRI(priority);
	IOVEC_SET_STRING(iovec[n++], syslog_priority);

	if (priority & LOG_FACMASK) {
		snprintf(syslog_facility, sizeof(syslog_facility), "SYSLOG_FACILITY=%i",
		    LOG_FAC(priority));
		IOVEC_SET_STRING(iovec[n++], syslog_facility);
	}

	if (s->identifier) {
		syslog_identifier = strappend("SYSLOG_IDENTIFIER=", s->identifier);
		if (syslog_identifier)
			IOVEC_SET_STRING(iovec[n++], syslog_identifier);
	}

	message = strappend("MESSAGE=", p);
	if (message)
		IOVEC_SET_STRING(iovec[n++], message);

#ifdef HAVE_SELINUX
	if (s->security_context) {
		label = (char *) s->security_context;
		label_len = strlen((char *) s->security_context);
	}
#endif

	server_dispatch_message(s->server, iovec, n, ELEMENTSOF(iovec), &s->ucred, NULL, label,
	    label_len, s->unit_id, priority, 0);
	return 0;
}

static int stdout_stream_line(StdoutStream *s, char *p)
{
	int r;

	assert(s);
	assert(p);

	p = strstrip(p);

	switch (s->state) {

	case STDOUT_STREAM_IDENTIFIER:
		if (isempty(p))
			s->identifier = NULL;
		else {
			s->identifier = strdup(p);
			if (!s->identifier)
				return log_oom();
		}

		s->state = STDOUT_STREAM_UNIT_ID;
		return 0;

	case STDOUT_STREAM_UNIT_ID:
		if (s->ucred.uid == 0) {
			if (isempty(p))
				s->unit_id = NULL;
			else {
				s->unit_id = strdup(p);
				if (!s->unit_id)
					return log_oom();
			}
		}

		s->state = STDOUT_STREAM_PRIORITY;
		return 0;

	case STDOUT_STREAM_PRIORITY:
		r = safe_atoi(p, &s->priority);
		if (r < 0 || s->priority < 0 || s->priority > 999) {
			log_warning("Failed to parse log priority line.");
			return -EINVAL;
		}

		s->state = STDOUT_STREAM_LEVEL_PREFIX;
		return 0;

	case STDOUT_STREAM_LEVEL_PREFIX:
		r = parse_boolean(p);
		if (r < 0) {
			log_warning("Failed to parse level prefix line.");
			return -EINVAL;
		}

		s->level_prefix = !!r;
		s->state = STDOUT_STREAM_FORWARD_TO_SYSLOG;
		return 0;

	case STDOUT_STREAM_FORWARD_TO_SYSLOG:
		r = parse_boolean(p);
		if (r < 0) {
			log_warning("Failed to parse forward to syslog line.");
			return -EINVAL;
		}

		s->forward_to_syslog = !!r;
		s->state = STDOUT_STREAM_FORWARD_TO_KMSG;
		return 0;

	case STDOUT_STREAM_FORWARD_TO_KMSG:
		r = parse_boolean(p);
		if (r < 0) {
			log_warning("Failed to parse copy to kmsg line.");
			return -EINVAL;
		}

		s->forward_to_kmsg = !!r;
		s->state = STDOUT_STREAM_FORWARD_TO_CONSOLE;
		return 0;

	case STDOUT_STREAM_FORWARD_TO_CONSOLE:
		r = parse_boolean(p);
		if (r < 0) {
			log_warning("Failed to parse copy to console line.");
			return -EINVAL;
		}

		s->forward_to_console = !!r;
		s->state = STDOUT_STREAM_RUNNING;
		return 0;

	case STDOUT_STREAM_RUNNING:
		return stdout_stream_log(s, p);
	}

	assert_not_reached("Unknown stream state");
}

static int stdout_stream_scan(StdoutStream *s, bool force_flush)
{
	char *p;
	size_t remaining;
	int r;

	assert(s);

	p = s->buffer;
	remaining = s->length;
	for (;;) {
		char *end;
		size_t skip;

		end = memchr(p, '\n', remaining);
		if (end)
			skip = end - p + 1;
		else if (remaining >= sizeof(s->buffer) - 1) {
			end = p + sizeof(s->buffer) - 1;
			skip = remaining;
		} else
			break;

		*end = 0;

		r = stdout_stream_line(s, p);
		if (r < 0)
			return r;

		remaining -= skip;
		p += skip;
	}

	if (force_flush && remaining > 0) {
		p[remaining] = 0;
		r = stdout_stream_line(s, p);
		if (r < 0)
			return r;

		p += remaining;
		remaining = 0;
	}

	if (p > s->buffer) {
		memmove(s->buffer, p, remaining);
		s->length = remaining;
	}

	return 0;
}

void stdout_stream_process(struct ev_loop *evloop, ev_io *watch, int revents)
{
	StdoutStream *s = watch->data;
	ssize_t l;
	int r;

	assert(s);

	if (revents != EV_READ) {
		log_error("Bad event for stdout stream: %d\n", revents);
		goto closeit;
	}

	l = read(s->watch.fd, s->buffer + s->length, sizeof(s->buffer) - 1 - s->length);
	if (l < 0) {

		if (errno == EAGAIN)
			return;

		log_warning("Failed to read from stream: %m");
		goto closeit;
	}

	if (l == 0) {
		r = stdout_stream_scan(s, true);
		goto closeit;
	}

	s->length += l;
	r = stdout_stream_scan(s, false);
	if (r >= 0)
		return; /* all OK */

closeit:
	stdout_stream_free(s);

	return;
}

void stdout_stream_free(StdoutStream *s)
{
	assert(s);

	if (s->server) {
		assert(s->server->n_stdout_streams > 0);
		s->server->n_stdout_streams--;
		IWLIST_REMOVE(StdoutStream, stdout_stream, s->server->stdout_streams, s);
	}

	if (s->watch.fd >= 0) {
		if (s->server)
			ev_io_stop(s->server->evloop, &s->watch);

		safe_close(s->watch.fd);
	}

#ifdef HAVE_SELINUX
	if (s->security_context)
		freecon(s->security_context);
#endif

	free(s->identifier);
	free(s->unit_id);
	free(s);
}

void stdout_stream_new(struct ev_loop *evloop, ev_io *watch, int revents)
{
	Server *s = watch->data;
	StdoutStream *stream;
	int fd, r;
	socklen_t len;

	assert(s);

	fd = accept(s->stdout_watch.fd, NULL, NULL);

	if (fd < 0) {
		if (errno == EAGAIN)
			return;

		log_error("Failed to accept stdout connection: %m");
		return;
	}

	r = fd_cloexec(fd, true);
	r = r < 0 ? r : fd_nonblock(fd, true);

	if (r < 0) {
		log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
		close(fd);
		return;
	}

	if (s->n_stdout_streams >= STDOUT_STREAMS_MAX) {
		log_warning("Too many stdout streams, refusing connection.");
		safe_close(fd);
		return;
	}

	stream = new0(StdoutStream, 1);
	if (!stream) {
		safe_close(fd);
		return (void) log_oom();
	}

	ev_io_init(&stream->watch, stdout_stream_process, fd, EV_READ);
	stream->watch.data = stream;

	len = sizeof(stream->ucred);
	r = socket_getpeercred(fd, &stream->ucred);
	if (r < 0) {
		log_error("Failed to determine peer credentials: %s", strerror(-r));
		goto fail;
	}

#ifdef HAVE_SELINUX
	if (getpeercon(fd, &stream->security_context) < 0 && errno != ENOPROTOOPT)
		log_error("Failed to determine peer security context: %m");
#endif

	if (shutdown(fd, SHUT_WR) < 0) {
		log_error("Failed to shutdown writing side of socket: %m");
		r = -errno;
		goto fail;
	}

	if (ev_io_start(s->evloop, &stream->watch) < 0) {
		log_error("Failed to add stream to event loop: %m");
		r = -errno;
		goto fail;
	}

	stream->server = s;
	IWLIST_PREPEND(StdoutStream, stdout_stream, s->stdout_streams, stream);
	s->n_stdout_streams++;

	return;

fail:
	stdout_stream_free(stream);
	return;
}

int server_open_stdout_socket(Server *s)
{
	int r;
	int fd;

	assert(s);

	if (s->stdout_watch.fd < 0) {
		union sockaddr_union sa = {
			.un.sun_family = AF_UNIX,
			.un.sun_path = INSTALL_PKGRUNSTATE_DIR "/journal/stdout",
		};

		fd = socket(AF_UNIX, SOCK_STREAM, 0);

		if (fd < 0) {
			log_error("socket() failed: %m");
			return -errno;
		}

		r = fd_cloexec(fd, true);
		r = r < 0 ? r : fd_nonblock(fd, true);

		if (r < 0) {
			log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
			close(fd);
			return r;
		}

		unlink(sa.un.sun_path);

		r = bind(fd, &sa.sa,
		    offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
		if (r < 0) {
			log_error("bind() stream failed: %m");
			return -errno;
		}

		chmod(sa.un.sun_path, 0666);

		if (listen(fd, SOMAXCONN) < 0) {
			log_error("listen() failed: %m");
			return -errno;
		}
	} else {
		fd = s->stdout_watch.fd;
		fd_nonblock(fd, 1);
	}

	ev_io_init(&s->stdout_watch, stdout_stream_new, fd, EV_READ);
	s->stdout_watch.data = s;
	if (ev_io_start(s->evloop, &s->stdout_watch) < 0) {
		log_error("Failed to add stdout server fd to event loop: %m");
		return -errno;
	}

	return 0;
}
