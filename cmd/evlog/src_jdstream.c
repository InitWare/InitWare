/*
 *    LICENCE NOTICE
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include "bsdqueue.h"
#include "compat.h"
#include "evlogd.h"
#include "socket-util.h"
#include "src_cred.h"
#include "src_jdstream.h"

/** What kind of line is being awaited. */
enum JDStreamClientAwaitState {
	kIdentifier = 0,
	kUnitId,
	kPriority,
	kParseLevelPrefix,
	kForwardSyslog,
	kForwardKmsg,
	kForwardCons,
	kLogLine,
};

typedef enum JDStreamClientAwaitState JDStreamClientAwaitState;

struct JDStreamClient {
	JDStream *jdstream;

	ev_io watch;
	JDStreamClientAwaitState awaiting;
	char buf[LINE_MAX];
	size_t bufread; /* how much text is in the buffer already */

	SourceMetadata metadata;
	int priority;
	char *syslog_identifier;

	TAILQ_ENTRY(JDStreamClient) entries;
};

typedef struct JDStreamClient JDStreamClient;

void jdstreamclient_free(JDStreamClient *self)
{
	TAILQ_REMOVE(&self->jdstream->clients, self, entries);
	ev_io_stop(self->jdstream->manager->evloop, &self->watch);
	safe_close(self->watch.fd);

	free(self->metadata.cmdline);
	free(self->metadata.command);
	free(self->metadata.exe);
	free(self->metadata.systemd_session);
	free(self->metadata.systemd_slice);
	free(self->metadata.systemd_unit);
	free(self->metadata.systemd_user_slice);
	free(self->metadata.systemd_user_unit);
	free(self);
}

static void jdstreamclient_read_line(JDStreamClient *self, const char *line)
{
	int r;

	switch (self->awaiting) {
	case kLogLine: {
		struct LogLine ll;
		ll.extra_fields_json = NULL;
		ll.boot_id = self->jdstream->manager->bootid;
		ll.hostname = self->jdstream->manager->hostname;
		ll.machine_id = self->jdstream->manager->machid;
		ll.message = line;
		ll.message_id = SD_ID128_NULL;
		ll.metadata = self->metadata;
		ll.priority = self->priority;
		ll.source_realtime_timestamp = -1;
		ll.syslog_identifier = self->syslog_identifier;
		ll.syslog_facility = -1;
		dual_timestamp_get(&ll.timestamp);
		ll.transport = kStdout;

		backend_insert(&self->jdstream->manager->backend, &ll);

		break;
	}

	case kIdentifier:
		if (!isempty(line)) {
			self->syslog_identifier = strdup(line);
			if (!self->syslog_identifier)
				return (void) log_oom();
		}
		self->awaiting = kUnitId;

		break;
	case kUnitId:
		if (!isempty(line) && self->metadata.cred.uid == 0) {
			self->metadata.systemd_unit = strdup(line);
			if (!self->metadata.systemd_unit)
				return (void) log_oom();
		}
		self->awaiting = kPriority;
		break;

	case kPriority:
		r = safe_atoi(line, &self->priority);
		if (r < 0)
			return (void) log_warning("Bad log priority line.");
		self->awaiting = kParseLevelPrefix;
		break;

	case kParseLevelPrefix:
		self->awaiting = kForwardSyslog;
		break;

	case kForwardSyslog:
		self->awaiting = kForwardKmsg;
		break;

	case kForwardKmsg:
		self->awaiting = kForwardCons;
		break;

	case kForwardCons:
		self->awaiting = kLogLine;
#ifndef CREDPASS_PERSISTS
		/* try to induce the passing of credentials again to mitigate #26 */
		socket_passcred(self->watch.fd);
#endif
		break;
	}
}

static void jdstreamclient_recv_cb(struct ev_loop *evloop, ev_io *watch, int revents)
{
	int r;
	JDStreamClient *self = watch->data;
	struct iovec iov = { self->buf + self->bufread, sizeof(self->buf) - self->bufread };
	union {
		struct cmsghdr cmsghdr;
#ifdef CMSG_CREDS_STRUCT
		uint8_t buf[CMSG_SPACE(CMSG_CREDS_STRUCT_SIZE)];
#endif
	} control = {};
	struct msghdr msghdr = { .msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &control,
		.msg_controllen = sizeof(control) };

	r = recvmsg(watch->fd, &msghdr, MSG_DONTWAIT);

	if (r == -1) {
		return (void) log_error("Failed to read from JournalD stream socket: %m\n");
	}
	if (r == 0) {
		log_info("EOF on JournalD stream socket client, dropping.\n");
		jdstreamclient_free(self);
	} else {
		char *line = self->buf, *line_end;

		self->bufread += r;

		r = cmsg_readucred(&control.cmsghdr, &self->metadata.cred);
		if (r) {
			log_info("Updating creds for PID %d.\n", self->metadata.cred.pid);
			/* creds updated; handle appropriately */
			sourcemetadata_update_from_pid(&self->metadata);
		}

		/* process line-by-line */
		while ((line_end = memchr(line, '\n', self->bufread - (line - self->buf)))) {
			*line_end = '\0';
			jdstreamclient_read_line(self, line);
			line = line_end + 1;
		}

		self->bufread -= (line - self->buf);

		if (self->bufread == sizeof(self->buf)) {
			/* buffer is full, therefore forcibly flush it */
			char_array_0(self->buf);
			jdstreamclient_read_line(self, self->buf);
			self->bufread = 0;
		} else
			memmove(self->buf, line, self->bufread);
	}
}

static void jdstream_connect_cb(struct ev_loop *evloop, ev_io *watch, int revents)
{
	JDStream *jds = watch->data;
	JDStreamClient *client;
	int fd;
	int r;

	assert(revents & EV_READ);
	fd = accept4(watch->fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0)
		return (void) log_error_errno(errno, "accept() failed: %m");

	client = new0(JDStreamClient, 1);
	if (!client) {
		safe_close(fd);
		return (void) log_oom();
	}

	client->jdstream = jds;
	ev_io_init(&client->watch, jdstreamclient_recv_cb, fd, EV_READ);
	client->watch.data = client;
	client->awaiting = kIdentifier;

	r = socket_getpeercred(fd, &client->metadata.cred);
	if (r < 0) {
		log_error("getpeercred() failed: %m");
		goto fail;
	}

	r = sourcemetadata_update_from_pid(&client->metadata);

	r = socket_passcred(fd);
	if (r < 0) {
		log_error("socket_passcred() failed: %m\n");
		goto fail;
	}

	r = ev_io_start(jds->manager->evloop, &client->watch);
	if (r < 0) {
		log_error("Failed to watch client: %m");
		goto fail;
	}

	TAILQ_INSERT_TAIL(&jds->clients, client, entries);
	log_info("Accepted new JournalD stream client (fd %d)\n", fd);

	return;

fail:
	free(client);
}

int jdstream_init(Evlogd *manager, JDStream *jds, int fd)
{
	int r;

	jds->manager = manager;
	jds->watch.fd = -1;
	TAILQ_INIT(&jds->clients);

	if (fd < 0) {
		union sockaddr_union sa = {
			.un.sun_family = AF_UNIX,
			.un.sun_path = JD_STREAM_SOCKET,
		};

		fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		if (fd < 0)
			return log_error_errno(errno, "socket() failed: %m");

		unlink(sa.un.sun_path);

		r = bind(fd, &sa.sa,
		    offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
		if (r < 0)
			return log_error_errno(errno, "bind() failed: %m");

		chmod(sa.un.sun_path, 0666);

		if (listen(fd, SOMAXCONN) < 0)
			return log_error_errno(errno, "listen() failed: %m");
	} else
		fd_nonblock(fd, 1);

	ev_io_init(&jds->watch, jdstream_connect_cb, fd, EV_READ);
	jds->watch.data = jds;

	r = ev_io_start(manager->evloop, &jds->watch);
	if (r < 0)
		return log_error_errno(-r, "Failed to add I/O event for stream: %m");

	return r;
}