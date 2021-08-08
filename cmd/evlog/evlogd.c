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
#include "log.h"
#include "src_jdstream.h"

Evlogd m;

static void manager_signal_cb(struct ev_loop *evloop, ev_signal *watch, int revents)
{
	log_info("Signalled, stopping.\n");
	ev_break(m.evloop, EVBREAK_ALL);
}

static int startup()
{
	int r;

	m.evloop = ev_default_loop(0);
	if (!m.evloop)
		return log_error_errno(ENOMEM, "Failed to create event loop: %m.\n");

	gethostname(m.hostname, 255);
	sd_id128_get_boot(&m.bootid);
	sd_id128_get_machine(&m.machid);

	ev_signal_init(&m.sigint, manager_signal_cb, SIGINT);
	ev_signal_init(&m.sigterm, manager_signal_cb, SIGTERM);
	assert_se(ev_signal_start(m.evloop, &m.sigint) == 0);
	assert_se(ev_signal_start(m.evloop, &m.sigterm) == 0);

	r = jdstream_init(&m, &m.jdstream, -1);
	if (r < 0)
		return r;

	r = backend_init(&m, &m.backend);
	if (r < 0)
		return r;

	return 0;
}

static int manager_shutdown()
{
	backend_shutdown(&m.backend);
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

	LogLine test;
	zero(test);
	test.message = "Hello World\n";
	test.hostname = "Localhost";
	backend_insert(&m.backend, &test);

	ev_run(m.evloop, 0);

finish:
	manager_shutdown();
	return r;
}