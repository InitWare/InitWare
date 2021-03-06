/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>

#include "strv.h"
#include "util.h"
#include "log.h"
#include "build.h"
#include "env-util.h"

static bool arg_ready = false;
static pid_t arg_pid = 0;
static const char *arg_status = NULL;
static bool arg_booted = false;

static int help(void) {

        printf("%s [OPTIONS...] [VARIABLE=VALUE...]\n\n"
               "Notify the init system about service status updates.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --ready            Inform the init system about service start-up completion\n"
               "     --pid[=PID]        Set main pid of daemon\n"
               "     --status=TEXT      Set status text\n"
               "     --booted           Returns 0 if the system was booted up with systemd, non-zero otherwise\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_READY = 0x100,
                ARG_VERSION,
                ARG_PID,
                ARG_STATUS,
                ARG_BOOTED,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "ready",     no_argument,       NULL, ARG_READY     },
                { "pid",       optional_argument, NULL, ARG_PID       },
                { "status",    required_argument, NULL, ARG_STATUS    },
                { "booted",    no_argument,       NULL, ARG_BOOTED    },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_READY:
                        arg_ready = true;
                        break;

                case ARG_PID:

                        if (optarg) {
                                if (parse_pid(optarg, &arg_pid) < 0) {
                                        log_error("Failed to parse PID %s.", optarg);
                                        return -EINVAL;
                                }
                        } else
                                arg_pid = getppid();

                        break;

                case ARG_STATUS:
                        arg_status = optarg;
                        break;

                case ARG_BOOTED:
                        arg_booted = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc &&
            !arg_ready &&
            !arg_status &&
            !arg_pid &&
            !arg_booted) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char* argv[]) {
        char* our_env[4], **final_env = NULL;
        unsigned i = 0;
        char *status = NULL, *cpid = NULL, *n = NULL;
        int r, retval = EXIT_FAILURE;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0) {
                retval = r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                goto finish;
        }

        if (arg_booted)
                return sd_booted() <= 0;

        if (arg_ready)
                our_env[i++] = (char*) "READY=1";

        if (arg_status) {
                if (!(status = strappend("STATUS=", arg_status))) {
                        log_error("Failed to allocate STATUS string.");
                        goto finish;
                }

                our_env[i++] = status;
        }

        if (arg_pid > 0) {
                if (asprintf(&cpid, "MAINPID=%lu", (unsigned long) arg_pid) < 0) {
                        log_error("Failed to allocate MAINPID string.");
                        goto finish;
                }

                our_env[i++] = cpid;
        }

        our_env[i++] = NULL;

        if (!(final_env = strv_env_merge(2, our_env, argv + optind))) {
                log_error("Failed to merge string sets.");
                goto finish;
        }

        if (strv_length(final_env) <= 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (!(n = strv_join(final_env, "\n"))) {
                log_error("Failed to concatenate strings.");
                goto finish;
        }

        if ((r = sd_notify(false, n)) < 0) {
                log_error("Failed to notify init system: %s", strerror(-r));
                goto finish;
        }

        retval = r <= 0 ? EXIT_FAILURE : EXIT_SUCCESS;

finish:
        free(status);
        free(cpid);
        free(n);

        strv_free(final_env);

        return retval;
}
