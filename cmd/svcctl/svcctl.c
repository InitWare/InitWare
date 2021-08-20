/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-shutdown.h>

#include "svcctl.h"
#include "log.h"
#include "build.h"
#include "dbus-common.h"
#include "initreq.h"
#include "list.h"
#include "macro.h"
#include "pager.h"
#include "socket-util.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "strv.h"
#include "unit-name.h"

#ifdef Have_sys_prctl_h
#        include <sys/prctl.h>
#endif

#ifdef Sys_Plat_NetBSD
#define reboot(m) reboot(m, NULL)
#endif

char **arg_types = NULL;
char **arg_states = NULL;
char **arg_properties = NULL;
bool arg_all = false;
bool original_stdout_is_tty;
enum dependency arg_dependency = DEPENDENCY_FORWARD;
const char *arg_job_mode = "replace";
UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
bool arg_no_block = false;
bool arg_no_legend = false;
bool arg_no_pager = false;
bool arg_no_wtmp = false;
bool arg_no_wall = false;
bool arg_no_reload = false;
bool arg_show_types = false;
bool arg_ignore_inhibitors = false;
bool arg_dry = false;
bool arg_quiet = false;
bool arg_full = false;
int arg_force = 0;
bool arg_ask_password = true;
bool arg_runtime = false;
char **arg_wall = NULL;
const char *arg_kill_who = NULL;
int arg_signal = SIGTERM;
const char *arg_root = NULL;
usec_t arg_when = 0;
enum action arg_action = ACTION_SYSTEMCTL;
enum transport arg_transport = TRANSPORT_NORMAL;
char *arg_host = NULL;
char *arg_user = NULL;
unsigned arg_lines = 10;
OutputMode arg_output = OUTPUT_SHORT;
bool arg_plain = false;

bool private_bus = false;

static const char usage_fmt[] =
    "%s [OPTIONS...] {COMMAND} ...\n\n"
    "Query or send control commands to the InitWare scheduler.\n\n"
    "  -h --help           Show this help\n"
    "     --version        Show package version\n"
    "  -t --type=TYPE      List only units of a particular type\n"
    "     --state=STATE    List only units with particular LOAD or SUB or ACTIVE state\n"
    "  -p --property=NAME  Show only properties by this name\n"
    "  -a --all            Show all loaded units/properties, including dead/empty\n"
    "                      ones. To list all units installed on the system, use\n"
    "                      the 'list-unit-files' command instead.\n"
    "     --reverse        Show reverse dependencies with 'list-dependencies'\n"
    "  -l --full           Don't ellipsize unit names on output\n"
    "     --fail           When queueing a new job, fail if conflicting jobs are\n"
    "                      pending\n"
    "     --irreversible   When queueing a new job, make sure it cannot be implicitly\n"
    "                      cancelled\n"
    "     --ignore-dependencies\n"
    "                      When queueing a new job, ignore all its dependencies\n"
    "     --show-types     When showing sockets, explicitly show their type\n"
    "  -i --ignore-inhibitors\n"
    "                      When shutting down or sleeping, ignore inhibitors\n"
    "     --kill-who=WHO   Who to send signal to\n"
    "  -s --signal=SIGNAL  Which signal to send\n"
    "  -H --host=[USER@]HOST\n"
    "                      Show information for remote host\n"
    "  -P --privileged     Acquire privileges before execution\n"
    "  -q --quiet          Suppress output\n"
    "     --no-block       Do not wait until operation finished\n"
    "     --no-wall        Don't send wall message before halt/power-off/reboot\n"
    "     --no-reload      When enabling/disabling unit files, don't reload daemon\n"
    "                      configuration\n"
    "     --no-legend      Do not print a legend (column headers and hints)\n"
    "     --no-pager       Do not pipe output into a pager\n"
    "     --no-ask-password\n"
    "                      Do not ask for system passwords\n"
    "     --system         Connect to system manager\n"
    "     --user           Connect to user service manager\n"
    "     --global         Enable/disable user unit files globally\n"
    "     --runtime        Enable unit files only temporarily until next reboot\n"
    "  -f --force          When enabling unit files, override existing symlinks\n"
    "                      When shutting down, execute action immediately\n"
    "     --root=PATH      Enable unit files in the specified root directory\n"
    "  -n --lines=INTEGER  Number of journal entries to show\n"
    "  -o --output=STRING  Change journal output mode (short, short-monotonic,\n"
    "                      verbose, export, json, json-pretty, json-sse, cat)\n"
    "     --plain          Print unit dependencies as a list instead of a tree\n\n"
    "Unit Commands:\n"
    "  list-units                      List loaded units\n"
    "  list-sockets                    List loaded sockets ordered by address\n"
    "  start [NAME...]                 Start (activate) one or more units\n"
    "  stop [NAME...]                  Stop (deactivate) one or more units\n"
    "  reload [NAME...]                Reload one or more units\n"
    "  restart [NAME...]               Start or restart one or more units\n"
    "  try-restart [NAME...]           Restart one or more units if active\n"
    "  reload-or-restart [NAME...]     Reload one or more units if possible,\n"
    "                                  otherwise start or restart\n"
    "  reload-or-try-restart [NAME...] Reload one or more units if possible,\n"
    "                                  otherwise restart if active\n"
    "  isolate [NAME]                  Start one unit and stop all others\n"
    "  kill [NAME...]                  Send signal to processes of a unit\n"
    "  is-active [NAME...]             Check whether units are active\n"
    "  is-failed [NAME...]             Check whether units are failed\n"
    "  status [NAME...|PID...]         Show runtime status of one or more units\n"
    "  show [NAME...|JOB...]           Show properties of one or more\n"
    "                                  units/jobs or the manager\n"
    "  set-property [NAME] [ASSIGNMENT...]\n"
    "                                  Sets one or more properties of a unit\n"
    "  help [NAME...|PID...]           Show manual for one or more units\n"
    "  reset-failed [NAME...]          Reset failed state for all, one, or more\n"
    "                                  units\n"
    "  list-dependencies [NAME]        Recursively show units which are required\n"
    "                                  or wanted by this unit or by which this\n"
    "                                  unit is required or wanted\n\n"
    "Unit File Commands:\n"
    "  list-unit-files                 List installed unit files\n"
    "  enable [NAME...]                Enable one or more unit files\n"
    "  disable [NAME...]               Disable one or more unit files\n"
    "  reenable [NAME...]              Reenable one or more unit files\n"
    "  preset [NAME...]                Enable/disable one or more unit files\n"
    "                                  based on preset configuration\n"
    "  is-enabled [NAME...]            Check whether unit files are enabled\n\n"
    "  mask [NAME...]                  Mask one or more units\n"
    "  unmask [NAME...]                Unmask one or more units\n"
    "  link [PATH...]                  Link one or more units files into\n"
    "                                  the search path\n"
    "  get-default                     Get the name of the default target\n"
    "  set-default NAME                Set the default target\n\n"
    "Job Commands:\n"
    "  list-jobs                       List jobs\n"
    "  cancel [JOB...]                 Cancel all, one, or more jobs\n\n"
    "Snapshot Commands:\n"
    "  snapshot [NAME]                 Create a snapshot\n"
    "  delete [NAME...]                Remove one or more snapshots\n\n"
    "Environment Commands:\n"
    "  show-environment                Dump environment\n"
    "  set-environment [NAME=VALUE...] Set one or more environment variables\n"
    "  unset-environment [NAME...]     Unset one or more environment variables\n\n"
    "Manager Lifecycle Commands:\n"
    "  daemon-reload                   Reload systemd manager configuration\n"
    "  daemon-reexec                   Reexecute systemd manager\n\n"
    "System Commands:\n"
    "  default                         Enter system default mode\n"
    "  rescue                          Enter system rescue mode\n"
    "  emergency                       Enter system emergency mode\n"
    "  halt                            Shut down and halt the system\n"
    "  poweroff                        Shut down and power-off the system\n"
    "  reboot                          Shut down and reboot the system\n"
    "  kexec                           Shut down and reboot the system with kexec\n"
    "  exit                            Request user instance exit\n"
    "  switch-root [ROOT] [INIT]       Change to a different root file system\n"
    "  suspend                         Suspend the system\n"
    "  hibernate                       Hibernate the system\n"
    "  hybrid-sleep                    Hibernate and suspend the system\n";

static int systemctl_help(void)
{
	pager_open_if_enabled();

	printf(usage_fmt, program_invocation_short_name);

	return 0;
}

static int halt_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "%s the system.\n\n"
               "     --help      Show this help\n"
               "     --halt      Halt the machine\n"
               "  -p --poweroff  Switch off the machine\n"
               "     --reboot    Reboot the machine\n"
               "  -f --force     Force immediate halt/power-off/reboot\n"
               "  -w --wtmp-only Don't halt/power-off/reboot, just write wtmp record\n"
               "  -d --no-wtmp   Don't write wtmp record\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n",
               program_invocation_short_name,
               arg_action == ACTION_REBOOT           ? "Reboot" :
                       arg_action == ACTION_POWEROFF ? "Power off" :
                                                       "Halt");

        return 0;
}

static int shutdown_help(void) {

        printf("%s [OPTIONS...] [TIME] [WALL...]\n\n"
               "Shut down the system.\n\n"
               "     --help      Show this help\n"
               "  -H --halt      Halt the machine\n"
               "  -P --poweroff  Power-off the machine\n"
               "  -r --reboot    Reboot the machine\n"
               "  -h             Equivalent to --poweroff, overridden by --halt\n"
               "  -k             Don't halt/power-off/reboot, just send warnings\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n"
               "  -c             Cancel a pending shutdown\n",
               program_invocation_short_name);

        return 0;
}

static int telinit_help(void) {

        printf("%s [OPTIONS...] {COMMAND}\n\n"
               "Send control commands to the init daemon.\n\n"
               "     --help      Show this help\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n\n"
               "Commands:\n"
               "  0              Power-off the machine\n"
               "  6              Reboot the machine\n"
               "  2, 3, 4, 5     Start runlevelX.target unit\n"
               "  1, s, S        Enter rescue mode\n"
               "  q, Q           Reload init daemon configuration\n"
               "  u, U           Reexecute init daemon\n",
               program_invocation_short_name);

        return 0;
}

static int runlevel_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Prints the previous and current runlevel of the init system.\n\n"
               "     --help      Show this help\n",
               program_invocation_short_name);

        return 0;
}

static int help_types(void) {
        int i;
        const char *t;

        puts("Available unit types:");
        for (i = 0; i < _UNIT_TYPE_MAX; i++) {
                t = unit_type_to_string(i);
                if (t)
                        puts(t);
        }

        return 0;
}

static int systemctl_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_FAIL = 0x100,
                ARG_REVERSE,
                ARG_AFTER,
                ARG_BEFORE,
                ARG_SHOW_TYPES,
                ARG_IRREVERSIBLE,
                ARG_IGNORE_DEPENDENCIES,
                ARG_VERSION,
                ARG_USER,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_NO_BLOCK,
                ARG_NO_LEGEND,
                ARG_NO_PAGER,
                ARG_NO_WALL,
                ARG_ROOT,
                ARG_NO_RELOAD,
                ARG_KILL_WHO,
                ARG_NO_ASK_PASSWORD,
                ARG_FAILED,
                ARG_RUNTIME,
                ARG_FORCE,
                ARG_PLAIN,
                ARG_STATE
        };

        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, ARG_VERSION },
                { "type", required_argument, NULL, 't' },
                { "property", required_argument, NULL, 'p' },
                { "all", no_argument, NULL, 'a' },
                { "reverse", no_argument, NULL, ARG_REVERSE },
                { "after", no_argument, NULL, ARG_AFTER },
                { "before", no_argument, NULL, ARG_BEFORE },
                { "show-types", no_argument, NULL, ARG_SHOW_TYPES },
                { "failed", no_argument, NULL, ARG_FAILED }, /* compatibility only */
                { "full", no_argument, NULL, 'l' },
                { "fail", no_argument, NULL, ARG_FAIL },
                { "irreversible", no_argument, NULL, ARG_IRREVERSIBLE },
                { "ignore-dependencies", no_argument, NULL, ARG_IGNORE_DEPENDENCIES },
                { "ignore-inhibitors", no_argument, NULL, 'i' },
                { "user", no_argument, NULL, ARG_USER },
                { "system", no_argument, NULL, ARG_SYSTEM },
                { "global", no_argument, NULL, ARG_GLOBAL },
                { "no-block", no_argument, NULL, ARG_NO_BLOCK },
                { "no-legend", no_argument, NULL, ARG_NO_LEGEND },
                { "no-pager", no_argument, NULL, ARG_NO_PAGER },
                { "no-wall", no_argument, NULL, ARG_NO_WALL },
                { "quiet", no_argument, NULL, 'q' },
                { "root", required_argument, NULL, ARG_ROOT },
                { "force", no_argument, NULL, ARG_FORCE },
                { "no-reload", no_argument, NULL, ARG_NO_RELOAD },
                { "kill-who", required_argument, NULL, ARG_KILL_WHO },
                { "signal", required_argument, NULL, 's' },
                { "no-ask-password", no_argument, NULL, ARG_NO_ASK_PASSWORD },
                { "host", required_argument, NULL, 'H' },
                { "privileged", no_argument, NULL, 'P' },
                { "runtime", no_argument, NULL, ARG_RUNTIME },
                { "lines", required_argument, NULL, 'n' },
                { "output", required_argument, NULL, 'o' },
                { "plain", no_argument, NULL, ARG_PLAIN },
                { "state", required_argument, NULL, ARG_STATE },
                { NULL, 0, NULL, 0 }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:p:alqfs:H:Pn:o:i", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        systemctl_help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 't': {
                        char *word, *state;
                        size_t size;

                        FOREACH_WORD_SEPARATOR(word, size, optarg, ",", state) {
                                _cleanup_free_ char *type;

                                type = strndup(word, size);
                                if (!type)
                                        return -ENOMEM;

                                if (streq(type, "help")) {
                                        help_types();
                                        return 0;
                                }

                                if (unit_type_from_string(type) >= 0) {
                                        if (strv_push(&arg_types, type))
                                                return log_oom();
                                        type = NULL;
                                        continue;
                                }

                                /* It's much nicer to use --state= for
                                 * load states, but let's support this
                                 * in --types= too for compatibility
                                 * with old versions */
                                if (unit_load_state_from_string(optarg) >= 0) {
                                        if (strv_push(&arg_states, type) < 0)
                                                return log_oom();
                                        type = NULL;
                                        continue;
                                }

                                log_error("Unknown unit type or load state '%s'.", type);
                                log_info("Use -t help to see a list of allowed values.");
                                return -EINVAL;
                        }

                        break;
                }

                case 'p': {
                        /* Make sure that if the empty property list
                           was specified, we won't show any properties. */
                        if (isempty(optarg) && !arg_properties) {
                                arg_properties = strv_new(NULL, NULL);
                                if (!arg_properties)
                                        return log_oom();
                        } else {
                                char *word, *state;
                                size_t size;

                                FOREACH_WORD_SEPARATOR(word, size, optarg, ",", state) {
                                        char *prop;

                                        prop = strndup(word, size);
                                        if (!prop)
                                                return log_oom();

                                        if (strv_push(&arg_properties, prop) < 0) {
                                                free(prop);
                                                return log_oom();
                                        }
                                }
                        }

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;

                        break;
                }

                case 'a':
                        arg_all = true;
                        break;

                case ARG_REVERSE:
                        arg_dependency = DEPENDENCY_REVERSE;
                        break;

                case ARG_AFTER:
                        arg_dependency = DEPENDENCY_AFTER;
                        break;

                case ARG_BEFORE:
                        arg_dependency = DEPENDENCY_BEFORE;
                        break;

                case ARG_SHOW_TYPES:
                        arg_show_types = true;
                        break;

                case ARG_FAIL:
                        arg_job_mode = "fail";
                        break;

                case ARG_IRREVERSIBLE:
                        arg_job_mode = "replace-irreversibly";
                        break;

                case ARG_IGNORE_DEPENDENCIES:
                        arg_job_mode = "ignore-dependencies";
                        break;

                case ARG_USER:
                        arg_scope = UNIT_FILE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_scope = UNIT_FILE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_scope = UNIT_FILE_GLOBAL;
                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_no_legend = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_FAILED:
                        if (strv_extend(&arg_states, "failed") < 0)
                                return log_oom();

                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_FORCE:
                        arg_force++;
                        break;

                case 'f':
                        arg_force++;
                        break;

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case 's':
                        if ((arg_signal = signal_from_string_try_harder(optarg)) < 0) {
                                log_error("Failed to parse signal string %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        parse_user_at_host(optarg, &arg_user, &arg_host);
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0) {
                                log_error("Failed to parse lines '%s'", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'o':
#if 0 /* FIXME */
                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output '%s'.", optarg);
                                return -EINVAL;
                        }
#endif
                        break;

                case 'i':
                        arg_ignore_inhibitors = true;
                        break;

                case ARG_PLAIN:
                        arg_plain = true;
                        break;

                case ARG_STATE: {
                        char *word, *state;
                        size_t size;

                        FOREACH_WORD_SEPARATOR(word, size, optarg, ",", state) {
                                char *s;

                                s = strndup(word, size);
                                if (!s)
                                        return log_oom();

                                if (strv_push(&arg_states, s) < 0) {
                                        free(s);
                                        return log_oom();
                                }
                        }
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code '%c'.", c);
                        return -EINVAL;
                }
        }

        if (arg_transport != TRANSPORT_NORMAL && arg_scope != UNIT_FILE_SYSTEM) {
                log_error("Cannot access user instance remotely.");
                return -EINVAL;
        }

        return 1;
}

static int halt_parse_argv(int argc, char *argv[]) {

        enum { ARG_HELP = 0x100, ARG_HALT, ARG_REBOOT, ARG_NO_WALL };

        static const struct option options[] = { { "help", no_argument, NULL, ARG_HELP },
                                                 { "halt", no_argument, NULL, ARG_HALT },
                                                 { "poweroff", no_argument, NULL, 'p' },
                                                 { "reboot", no_argument, NULL, ARG_REBOOT },
                                                 { "force", no_argument, NULL, 'f' },
                                                 { "wtmp-only", no_argument, NULL, 'w' },
                                                 { "no-wtmp", no_argument, NULL, 'd' },
                                                 { "no-wall", no_argument, NULL, ARG_NO_WALL },
                                                 { NULL, 0, NULL, 0 } };

        int c, runlevel;

        assert(argc >= 0);
        assert(argv);

#ifdef Use_UTmp
        if (utmp_get_runlevel(&runlevel, NULL) >= 0)
                if (runlevel == '0' || runlevel == '6')
                        arg_force = 2;
#endif

        while ((c = getopt_long(argc, argv, "pfwdnih", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        halt_help();
                        return 0;

                case ARG_HALT:
                        arg_action = ACTION_HALT;
                        break;

                case 'p':
                        if (arg_action != ACTION_REBOOT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case ARG_REBOOT:
                        arg_action = ACTION_REBOOT;
                        break;

                case 'f':
                        arg_force = 2;
                        break;

                case 'w':
                        arg_dry = true;
                        break;

                case 'd':
                        arg_no_wtmp = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'i':
                case 'h':
                case 'n':
                        /* Compatibility nops */
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code '%c'.", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int parse_time_spec(const char *t, usec_t *_u) {
        assert(t);
        assert(_u);

        if (streq(t, "now"))
                *_u = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *_u = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;
                struct tm tm = {};
                time_t s;
                usec_t n;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno > 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e + 1, &e, 10);
                if (errno > 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                n = now(CLOCK_REALTIME);
                s = (time_t)(n / USEC_PER_SEC);

                assert_se(localtime_r(&s, &tm));

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                assert_se(s = mktime(&tm));

                *_u = (usec_t) s * USEC_PER_SEC;

                while (*_u <= n)
                        *_u += USEC_PER_DAY;
        }

        return 0;
}

static int shutdown_parse_argv(int argc, char *argv[]) {

        enum { ARG_HELP = 0x100, ARG_NO_WALL };

        static const struct option options[] = {
                { "help", no_argument, NULL, ARG_HELP },       { "halt", no_argument, NULL, 'H' },
                { "poweroff", no_argument, NULL, 'P' },        { "reboot", no_argument, NULL, 'r' },
                { "kexec", no_argument, NULL, 'K' }, /* not documented extension */
                { "no-wall", no_argument, NULL, ARG_NO_WALL }, { NULL, 0, NULL, 0 }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "HPrhkt:afFc", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        shutdown_help();
                        return 0;

                case 'H':
                        arg_action = ACTION_HALT;
                        break;

                case 'P':
                        arg_action = ACTION_POWEROFF;
                        break;

                case 'r':
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        break;

                case 'K':
                        arg_action = ACTION_KEXEC;
                        break;

                case 'h':
                        if (arg_action != ACTION_HALT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case 'k':
                        arg_dry = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 't':
                case 'a':
                        /* Compatibility nops */
                        break;

                case 'c':
                        arg_action = ACTION_CANCEL_SHUTDOWN;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code '%c'.", c);
                        return -EINVAL;
                }
        }

        if (argc > optind && arg_action != ACTION_CANCEL_SHUTDOWN) {
                r = parse_time_spec(argv[optind], &arg_when);
                if (r < 0) {
                        log_error("Failed to parse time specification: %s", argv[optind]);
                        return r;
                }
        } else
                arg_when = now(CLOCK_REALTIME) + USEC_PER_MINUTE;

        if (argc > optind && arg_action == ACTION_CANCEL_SHUTDOWN)
                /* No time argument for shutdown cancel */
                arg_wall = argv + optind;
        else if (argc > optind + 1)
                /* We skip the time argument */
                arg_wall = argv + optind + 1;

        optind = argc;

        return 1;
}

static int telinit_parse_argv(int argc, char *argv[]) {

        enum { ARG_HELP = 0x100, ARG_NO_WALL };

        static const struct option options[] = { { "help", no_argument, NULL, ARG_HELP },
                                                 { "no-wall", no_argument, NULL, ARG_NO_WALL },
                                                 { NULL, 0, NULL, 0 } };

        static const struct {
                char from;
                enum action to;
        } table[] = { { '0', ACTION_POWEROFF },  { '6', ACTION_REBOOT },    { '1', ACTION_RESCUE },
                      { '2', ACTION_RUNLEVEL2 }, { '3', ACTION_RUNLEVEL3 }, { '4', ACTION_RUNLEVEL4 },
                      { '5', ACTION_RUNLEVEL5 }, { 's', ACTION_RESCUE },    { 'S', ACTION_RESCUE },
                      { 'q', ACTION_RELOAD },    { 'Q', ACTION_RELOAD },    { 'u', ACTION_REEXEC },
                      { 'U', ACTION_REEXEC } };

        unsigned i;
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        telinit_help();
                        return 0;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code '%c'.", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                telinit_help();
                return -EINVAL;
        }

        if (optind + 1 < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        if (strlen(argv[optind]) != 1) {
                log_error("Expected single character argument.");
                return -EINVAL;
        }

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].from == argv[optind][0])
                        break;

        if (i >= ELEMENTSOF(table)) {
                log_error("Unknown command '%s'.", argv[optind]);
                return -EINVAL;
        }

        arg_action = table[i].to;

        optind++;

        return 1;
}

static int runlevel_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
        };

        static const struct option options[] = { { "help", no_argument, NULL, ARG_HELP },
                                                 { NULL, 0, NULL, 0 } };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        runlevel_help();
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code '%c'.", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        if (program_invocation_short_name) {

                if (strstr(program_invocation_short_name, "halt")) {
                        arg_action = ACTION_HALT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "poweroff")) {
                        arg_action = ACTION_POWEROFF;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "reboot")) {
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "shutdown")) {
                        arg_action = ACTION_POWEROFF;
                        return shutdown_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "init")) {

                        if (sd_booted() > 0) {
                                arg_action = ACTION_INVALID;
                                return telinit_parse_argv(argc, argv);
                        } else {
                                /* Hmm, so some other init system is
                                 * running, we need to forward this
                                 * request to it. For now we simply
                                 * guess that it is Upstart. */

#ifdef TELINIT
                                execv(TELINIT, argv);
#endif

                                log_error("Couldn't find an alternative telinit implementation to spawn.");
                                return -EIO;
                        }

                } else if (strstr(program_invocation_short_name, "runlevel")) {
                        arg_action = ACTION_RUNLEVEL;
                        return runlevel_parse_argv(argc, argv);
                }
        }

        arg_action = ACTION_SYSTEMCTL;
        return systemctl_parse_argv(argc, argv);
}

_pure_ static int action_to_runlevel(void) {

        static const char table[_ACTION_MAX] = {
                [ACTION_HALT] = '0',      [ACTION_POWEROFF] = '0',  [ACTION_REBOOT] = '6',
                [ACTION_RUNLEVEL2] = '2', [ACTION_RUNLEVEL3] = '3', [ACTION_RUNLEVEL4] = '4',
                [ACTION_RUNLEVEL5] = '5', [ACTION_RESCUE] = '1'
        };

        assert(arg_action < _ACTION_MAX);

        return table[arg_action];
}

static int talk_initctl(void) {
        struct init_request request = {};
        int r;
        _cleanup_close_ int fd = -1;
        char rl;

        rl = action_to_runlevel();
        if (!rl)
                return 0;

        request.magic = INIT_MAGIC;
        request.sleeptime = 0;
        request.cmd = INIT_CMD_RUNLVL;
        request.runlevel = rl;

        fd = open(INIT_FIFO, O_WRONLY | O_NDELAY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open " INIT_FIFO ": %m");
                return -errno;
        }

        errno = 0;
        r = loop_write(fd, &request, sizeof(request), false) != sizeof(request);
        if (r) {
                log_error("Failed to write to " INIT_FIFO ": %m");
                return errno > 0 ? -errno : -EIO;
        }

        return 1;
}

static int systemctl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

        static const struct {
                const char *verb;
                const enum { MORE, LESS, EQUAL } argc_cmp;
                const int argc;
                int (*const dispatch)(DBusConnection *bus, char **args);
        } verbs[] = {
                { "list-units", LESS, 1, list_units },
                { "list-unit-files", EQUAL, 1, list_unit_files },
                { "list-sockets", LESS, 1, list_sockets },
                { "list-jobs", EQUAL, 1, list_jobs },
                { "clear-jobs", EQUAL, 1, daemon_reload },
                { "cancel", MORE, 2, cancel_job },
                { "start", MORE, 2, start_unit },
                { "stop", MORE, 2, start_unit },
                { "condstop", MORE, 2, start_unit }, /* For compatibility with ALTLinux */
                { "reload", MORE, 2, start_unit },
                { "restart", MORE, 2, start_unit },
                { "try-restart", MORE, 2, start_unit },
                { "reload-or-restart", MORE, 2, start_unit },
                { "reload-or-try-restart", MORE, 2, start_unit },
                { "force-reload", MORE, 2, start_unit }, /* For compatibility with SysV */
                { "condreload", MORE, 2, start_unit },   /* For compatibility with ALTLinux */
                { "condrestart", MORE, 2, start_unit },  /* For compatibility with RH */
                { "isolate", EQUAL, 2, start_unit },
                { "kill", MORE, 2, kill_unit },
                { "is-active", MORE, 2, check_unit_active },
                { "check", MORE, 2, check_unit_active },
                { "is-failed", MORE, 2, check_unit_failed },
                { "show", MORE, 1, show },
                { "status", MORE, 1, show },
                { "help", MORE, 2, show },
                { "snapshot", LESS, 2, snapshot },
                { "delete", MORE, 2, delete_snapshot },
                { "daemon-reload", EQUAL, 1, daemon_reload },
                { "daemon-reexec", EQUAL, 1, daemon_reload },
                { "show-environment", EQUAL, 1, show_environment },
                { "set-environment", MORE, 2, set_environment },
                { "unset-environment", MORE, 2, set_environment },
                { "halt", EQUAL, 1, start_special },
                { "poweroff", EQUAL, 1, start_special },
                { "reboot", EQUAL, 1, start_special },
                { "kexec", EQUAL, 1, start_special },
                { "suspend", EQUAL, 1, start_special },
                { "hibernate", EQUAL, 1, start_special },
                { "hybrid-sleep", EQUAL, 1, start_special },
                { "default", EQUAL, 1, start_special },
                { "rescue", EQUAL, 1, start_special },
                { "emergency", EQUAL, 1, start_special },
                { "exit", EQUAL, 1, start_special },
                { "reset-failed", MORE, 1, reset_failed },
                { "enable", MORE, 2, enable_unit },
                { "disable", MORE, 2, enable_unit },
                { "is-enabled", MORE, 2, unit_is_enabled },
                { "reenable", MORE, 2, enable_unit },
                { "preset", MORE, 2, enable_unit },
                { "mask", MORE, 2, enable_unit },
                { "unmask", MORE, 2, enable_unit },
                { "link", MORE, 2, enable_unit },
                { "switch-root", MORE, 2, switch_root },
                { "list-dependencies", LESS, 2, list_dependencies },
                { "set-default", EQUAL, 2, enable_unit },
                { "get-default", LESS, 1, get_default },
                { "set-property", MORE, 3, set_property },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-units" */
                i = 0;
        else {
                if (streq(argv[optind], "help") && !argv[optind + 1]) {
                        log_error(
                                "This command expects one or more "
                                "unit names. Did you mean --help?");
                        return -EINVAL;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation '%s'.", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        /* Require a bus connection for all operations but
         * enable/disable */
	if (!streq(verbs[i].verb, "enable") && !streq(verbs[i].verb, "disable") &&
	    !streq(verbs[i].verb, "is-enabled") && !streq(verbs[i].verb, "list-unit-files") &&
	    !streq(verbs[i].verb, "reenable") && !streq(verbs[i].verb, "preset") &&
	    !streq(verbs[i].verb, "mask") && !streq(verbs[i].verb, "unmask") &&
	    !streq(verbs[i].verb, "link") && !streq(verbs[i].verb, "set-default") &&
	    !streq(verbs[i].verb, "get-default")) {

		if (running_in_chroot() > 0) {
			log_info("Running in chroot, ignoring request.");
			return 0;
		}

		if (((!streq(verbs[i].verb, "reboot") && !streq(verbs[i].verb, "halt") &&
			 !streq(verbs[i].verb, "poweroff")) ||
			arg_force <= 0) &&
		    !bus) {
			log_error("Failed to get D-Bus connection: %s",
			    dbus_error_is_set(error) ? error->message :
							     "No connection to service manager.");
			return -EIO;
		}
	} else {

		// Deleted - consider a --no-dbus command line switch maybe?
		if (!bus && false /* !avoid_bus() */) {
			log_error("Failed to get D-Bus connection: %s",
			    dbus_error_is_set(error) ? error->message :
							     "No connection to service manager.");
			return -EIO;
		}
	}

	return verbs[i].dispatch(bus, argv + optind);
}

static int send_shutdownd(usec_t t, char mode, bool dry_run, bool warn, const char *message) {
        _cleanup_close_ int fd;
        struct sd_shutdown_command c = {
                .usec = t,
                .mode = mode,
                .dry_run = dry_run,
                .warn_wall = warn,
        };
	union sockaddr_union sockaddr = {
		.un.sun_family = AF_UNIX,
		.un.sun_path = INSTALL_PKGRUNSTATE_DIR "/shutdownd",
	};
	struct iovec iovec[2] = { {
                .iov_base = (char *) &c,
                .iov_len = offsetof(struct sd_shutdown_command, wall_message),
        } };
	struct msghdr msghdr = {
		.msg_name = &sockaddr,
		.msg_namelen = offsetof(struct sockaddr_un, sun_path) +
		    sizeof(INSTALL_PKGRUNSTATE_DIR "/shutdownd") - 1,
		.msg_iov = iovec,
		.msg_iovlen = 1,
	};
        int r;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0)
                return -errno;

	r = fd_cloexec(fd, true);
	r = r < 0 ? r : fd_nonblock(fd, true);

	if (r < 0) {
		log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
		close(fd);
		return r;
	}

        if (!isempty(message)) {
                iovec[1].iov_base = (char *) message;
                iovec[1].iov_len = strlen(message);
                msghdr.msg_iovlen++;
        }

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int reload_with_fallback(DBusConnection *bus) {

        if (bus) {
                /* First, try systemd via D-Bus. */
                if (daemon_reload(bus, NULL) >= 0)
                        return 0;
        }

        /* Nothing else worked, so let's try signals */
        assert(arg_action == ACTION_RELOAD || arg_action == ACTION_REEXEC);

        if (kill(1, arg_action == ACTION_RELOAD ? SIGHUP : SIGTERM) < 0) {
                log_error("kill() failed: %m");
                return -errno;
        }

        return 0;
}

static int start_with_fallback(DBusConnection *bus) {

        if (bus) {
                /* First, try systemd via D-Bus. */
                if (start_unit(bus, NULL) >= 0)
                        goto done;
        }

        /* Nothing else worked, so let's try
         * /dev/initctl */
        if (talk_initctl() > 0)
                goto done;

        log_error("Failed to talk to init daemon.");
        return -EIO;

done:
        warn_wall(arg_action);
        return 0;
}

_noreturn_ void halt_now(enum action a) {

        /* Make sure C-A-D is handled by the kernel from this
         * point on... */
#ifdef RB_ENABLE_CAD
        reboot(RB_ENABLE_CAD);
#endif

        switch (a) {

#ifdef RB_HALT
#define RB_HALT_SYSTEM RB_HALT
#endif

#ifdef RB_HALT_SYSTEM
        case ACTION_HALT:
                log_info("Halting.");
                reboot(RB_HALT_SYSTEM);
                break;
#endif

#ifdef RB_POWEROFF
#define RB_POWER_OFF RB_POWEROFF
#endif
#ifdef RB_POWEROFF
        case ACTION_POWEROFF:
                log_info("Powering off.");
                reboot(RB_POWER_OFF);
                break;
#endif

        case ACTION_REBOOT:
                log_info("Rebooting.");
                reboot(RB_AUTOBOOT);
                break;

        default:
                assert_not_reached("Unknown halt action.");
        }

        assert_not_reached("Uh? This shouldn't happen.");
}

static int halt_main(DBusConnection *bus) {
        int r;

        r = check_inhibitors(bus, arg_action);
        if (r < 0)
                return r;

        if (geteuid() != 0) {
                /* Try logind if we are a normal user and no special
                 * mode applies. Maybe PolicyKit allows us to shutdown
                 * the machine. */

                if (arg_when <= 0 && !arg_dry && arg_force <= 0 &&
                    (arg_action == ACTION_POWEROFF || arg_action == ACTION_REBOOT)) {
                        r = reboot_with_logind(bus, arg_action);
                        if (r >= 0)
                                return r;
                }

                log_error("Must be root.");
                return -EPERM;
        }

        if (arg_when > 0) {
                _cleanup_free_ char *m;

                m = strv_join(arg_wall, " ");
                r = send_shutdownd(
                        arg_when,
                        arg_action == ACTION_HALT             ? 'H' :
                                arg_action == ACTION_POWEROFF ? 'P' :
                                arg_action == ACTION_KEXEC    ? 'K' :
                                                                'r',
                        arg_dry,
                        !arg_no_wall,
                        m);

                if (r < 0)
                        log_warning(
                                "Failed to talk to shutdownd, proceeding with immediate shutdown: %s",
                                strerror(-r));
                else {
                        char date[FORMAT_TIMESTAMP_MAX];

                        log_info(
                                "Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                format_timestamp(date, sizeof(date), arg_when));
                        return 0;
                }
        }

        if (!arg_dry && !arg_force)
                return start_with_fallback(bus);

        if (!arg_no_wtmp) {
                if (sd_booted() > 0)
                        log_debug("Not writing utmp record, assuming that systemd-update-utmp is used.");
                else {
#ifdef Use_UTmp
                        r = utmp_put_shutdown();
                        if (r < 0)
#endif
                                log_warning("Failed to write utmp record: %s", strerror(-r));
                }
        }

        if (arg_dry)
                return 0;

        halt_now(arg_action);
        /* We should never reach this. */
        return -ENOSYS;
}

static int runlevel_main(void) {

#ifdef Have_UTmp
        int r, runlevel, previous;

        r = utmp_get_runlevel(&runlevel, &previous);
        if (r < 0) {
                puts("unknown");
                return r;
        }

        printf("%c %c\n", previous <= 0 ? 'N' : previous, runlevel <= 0 ? 'N' : runlevel);
#else
        printf("No Runlevel\n");
#endif

        return 0;
}

int main(int argc, char *argv[]) {
        int r, retval = EXIT_FAILURE;
        DBusConnection *bus = NULL;
        _cleanup_dbus_error_free_ DBusError error;

        dbus_error_init(&error);

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        /* Explicitly not on_tty() to avoid setting cached value.
         * This becomes relevant for piping output which might be
         * ellipsized. */
        original_stdout_is_tty = isatty(STDOUT_FILENO);

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        /* /sbin/runlevel doesn't need to communicate via D-Bus, so
         * let's shortcut this */
        if (arg_action == ACTION_RUNLEVEL) {
                r = runlevel_main();
                retval = r < 0 ? EXIT_FAILURE : r;
                goto finish;
        }

        if (running_in_chroot() > 0 && arg_action != ACTION_SYSTEMCTL) {
                log_info("Running in chroot, ignoring request.");
                retval = 0;
                goto finish;
        }

        if (!avoid_bus()) {
                if (arg_transport == TRANSPORT_NORMAL)
                        bus_connect(
                                arg_scope == UNIT_FILE_SYSTEM ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION,
                                &bus,
                                &private_bus,
                                &error);
                else if (arg_transport == TRANSPORT_POLKIT) {
                        bus_connect_system_polkit(&bus, &error);
                        private_bus = false;
                } else if (arg_transport == TRANSPORT_SSH) {
                        bus_connect_system_ssh(arg_user, arg_host, &bus, &error);
                        private_bus = false;
                } else
                        assert_not_reached("Uh, invalid transport...");
        }

        switch (arg_action) {

        case ACTION_SYSTEMCTL:
                r = systemctl_main(bus, argc, argv, &error);
                break;

        case ACTION_HALT:
        case ACTION_POWEROFF:
        case ACTION_REBOOT:
        case ACTION_KEXEC:
                r = halt_main(bus);
                break;

        case ACTION_RUNLEVEL2:
        case ACTION_RUNLEVEL3:
        case ACTION_RUNLEVEL4:
        case ACTION_RUNLEVEL5:
        case ACTION_RESCUE:
        case ACTION_EMERGENCY:
        case ACTION_DEFAULT:
                r = start_with_fallback(bus);
                break;

        case ACTION_RELOAD:
        case ACTION_REEXEC:
                r = reload_with_fallback(bus);
                break;

        case ACTION_CANCEL_SHUTDOWN: {
                char *m = NULL;

                if (arg_wall) {
                        m = strv_join(arg_wall, " ");
                        if (!m) {
                                retval = EXIT_FAILURE;
                                goto finish;
                        }
                }
                r = send_shutdownd(arg_when, SD_SHUTDOWN_NONE, false, !arg_no_wall, m);
                if (r < 0)
                        log_warning(
                                "Failed to talk to shutdownd, shutdown hasn't been cancelled: %s",
                                strerror(-r));
                free(m);
                break;
        }

        case ACTION_INVALID:
        case ACTION_RUNLEVEL:
        default:
                assert_not_reached("Unknown action");
        }

        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_shutdown();

        strv_free(arg_types);
        strv_free(arg_states);
        strv_free(arg_properties);

        pager_close();
        ask_password_agent_close();
        polkit_agent_close();

        return retval;
}
