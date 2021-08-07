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
/**
 * Entry point of the Event Log Daemon.
 */

#include <unistd.h>

#include "evlogd.h"
#include "jd_stream.h"
#include "log.h"

Evlogd m;

static int startup()
{
	int r;

	m.evloop = ev_default_loop(0);
	if (!m.evloop)
		return log_error_errno(ENOMEM, "Failed to create event loop: %m.\n");

	r = jdstream_init(&m, &m.jdstream, -1);
	if (r < 0)
		return r;

	r = backend_init(&m, &m.bend);
	if (r < 0)
		return r;

	return 0;
}

int main(int argc, char *argv[])
{
	int r;

	log_set_target(LOG_TARGET_SAFE);
	log_set_facility(LOG_SYSLOG);
	log_show_color(isatty(STDERR_FILENO) > 0);
	log_parse_environment();
	log_open();

	umask(0022);

	log_info("Event Log daemon (" PACKAGE_STRING ") starting.\n");

	r = startup();
	if (r < 0) {
		log_error("Failed to start up daemon; exiting.\n");
		goto finish;
	}

finish:
	return r;
}