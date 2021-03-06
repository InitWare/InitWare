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

#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-messages.h>

#include "journal-authenticate.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-syslog.h"

int main(int argc, char *argv[])
{
	Server server;
	int r;

	/* if (getppid() != 1) { */
	/*         log_error("This program should be invoked by init only."); */
	/*         return EXIT_FAILURE; */
	/* } */

	if (argc > 1) {
		log_error("This program does not take arguments.");
		return EXIT_FAILURE;
	}

	log_set_target(LOG_TARGET_SAFE);
	log_set_facility(LOG_SYSLOG);
	log_set_max_level(LOG_DEBUG);
	log_parse_environment();
	log_open();

	umask(0022);

	r = server_init(&server);
	if (r < 0)
		goto finish;

	server_vacuum(&server);
	server_flush_to_var(&server);
	server_flush_dev_kmsg(&server);

	log_debug("systemd-journald running as pid %lu", (unsigned long) getpid());
	server_driver_message(&server, SD_MESSAGE_JOURNAL_START, "Journal started");

	sd_notify(false,
	    "READY=1\n"
	    "STATUS=Processing requests...");

	for (;;) {
		int t = -1;
		usec_t n;

		n = now(CLOCK_REALTIME);

		if (server.max_retention_usec > 0 && server.oldest_file_usec > 0) {

			/* The retention time is reached, so let's vacuum! */
			if (server.oldest_file_usec + server.max_retention_usec < n) {
				log_info("Retention time reached.");
				server_rotate(&server);
				server_vacuum(&server);
				continue;
			}

			/* Calculate when to rotate the next time */
			t = (int) ((server.oldest_file_usec + server.max_retention_usec - n +
				       USEC_PER_MSEC - 1) /
			    USEC_PER_MSEC);
		}

#ifdef HAVE_GCRYPT
		if (server.system_journal) {
			usec_t u;

			if (journal_file_next_evolve_usec(server.system_journal, &u)) {
				if (n >= u)
					t = 0;
				else
					t = MIN(t,
					    (int) ((u - n + USEC_PER_MSEC - 1) / USEC_PER_MSEC));
			}
		}
#endif

		r = ev_run(server.evloop, EVRUN_ONCE);
		if (r < 0) {

			if (errno == EINTR)
				continue;

			log_error("ev_run() failed: %m");
			r = -errno;
			goto finish;
		}

		server_maybe_append_tags(&server);
		server_maybe_warn_forward_syslog_missed(&server);

		if (server.to_quit)
			break;
	}

	log_debug("systemd-journald stopped as pid %lu", (unsigned long) getpid());
	server_driver_message(&server, SD_MESSAGE_JOURNAL_STOP, "Journal stopped");

finish:
	sd_notify(false, "STATUS=Shutting down...");

	server_done(&server);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
