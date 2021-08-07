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

#include "compat.h"
#include "evlogd.h"
#include "jd_stream.h"
#include "socket-util.h"

static void jdstream_connect_cb(struct ev_loop *evloop, ev_io *ev, int revents)
{
	JDStream *jds = ev->data;

	assert(revents & EV_READ);
	log_info("Connection on journald stream socket.\n");
}


int jdstream_init(Evlogd *manager, JDStream *jds, int fd)
{
	int r;

	jds->manager = manager;
	jds->watch.fd = -1;

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