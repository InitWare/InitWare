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

#include <getopt.h>
#include <stdio.h>

#include <dbus/dbus.h>

#include "build.h"
#include "def.h"
#include "dbus-common.h"
#include "path-util.h"
#include "strv.h"
#include "unit-name.h"

static bool arg_scope = false;
static bool arg_user = false;
static bool arg_remain_after_exit = false;
static const char *arg_unit = NULL;
static const char *arg_description = NULL;
static const char *arg_slice = NULL;
static bool arg_send_sighup = false;
static bool private_bus = false;

static int help(void) {

        printf("%s [OPTIONS...] COMMAND [ARGS...]\n\n"
               "Run the specified command in a transient scope or service unit.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --user               Run as user unit\n"
               "     --scope              Run this as scope rather than service\n"
               "     --unit=UNIT          Run under the specified unit name\n"
               "     --description=TEXT   Description for unit\n"
               "     --slice=SLICE        Run in the specified slice\n"
               "  -r --remain-after-exit  Leave service around until explicitly stopped\n"
               "     --send-sighup        Send SIGHUP when terminating\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_SCOPE,
                ARG_UNIT,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SEND_SIGHUP,
        };

        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, ARG_VERSION },
                { "user", no_argument, NULL, ARG_USER },
                { "system", no_argument, NULL, ARG_SYSTEM },
                { "scope", no_argument, NULL, ARG_SCOPE },
                { "unit", required_argument, NULL, ARG_UNIT },
                { "description", required_argument, NULL, ARG_DESCRIPTION },
                { "slice", required_argument, NULL, ARG_SLICE },
                { "remain-after-exit", no_argument, NULL, 'r' },
                { "send-sighup", no_argument, NULL, ARG_SEND_SIGHUP },
                { NULL, 0, NULL, 0 },
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hr", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case ARG_SCOPE:
                        arg_scope = true;
                        break;

                case ARG_UNIT:
                        arg_unit = optarg;
                        break;

                case ARG_DESCRIPTION:
                        arg_description = optarg;
                        break;

                case ARG_SLICE:
                        arg_slice = optarg;
                        break;

                case ARG_SEND_SIGHUP:
                        arg_send_sighup = true;
                        break;

                case 'r':
                        arg_remain_after_exit = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                log_error("Command line to execute required.");
                return -EINVAL;
        }

        return 1;
}

static int string_property(DBusMessageIter *sub, const char *key, const char *value) {
        DBusMessageIter sub2, sub3, sub4;
        if (!dbus_message_iter_open_container(sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &key) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &value) ||
            !dbus_message_iter_close_container(&sub2, &sub3) || !dbus_message_iter_close_container(sub, &sub2))
                return log_oom();
        return 0;
}

static int message_start_transient_unit_new(
        DBusConnection *bus, const char *name, DBusMessage **ret, DBusMessageIter *args, DBusMessageIter *props) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        DBusMessageIter sub, sub2, sub3, sub4;
        int r;
        const char *fail_property = "fail";

        log_info("Running as unit %s.", name);

        m = dbus_message_new_method_call(
                SCHEDULER_DBUS_BUSNAME,
                "/org/freedesktop/systemd1",
                SCHEDULER_DBUS_INTERFACE ".Manager",
                "StartTransientUnit");
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, args);

        if (!dbus_message_iter_append_basic(args, DBUS_TYPE_STRING, &name) ||
            !dbus_message_iter_append_basic(args, DBUS_TYPE_STRING, &fail_property))
                return log_oom();

        if (!dbus_message_iter_open_container(args, DBUS_TYPE_ARRAY, "(sv)", props))
                return log_oom();

        string_property(props, "Description", arg_description);

        if (!isempty(arg_slice)) {
                _cleanup_free_ char *slice;

                slice = unit_name_mangle_with_suffix(arg_slice, ".slice");
                if (!slice)
                        return log_oom();

                r = string_property(props, "Slice", slice);
                if (r < 0)
                        return r;
        }

#if 0
        r = sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", arg_send_sighup);
        if (r < 0)
                return r;
#endif

        *ret = m;
        m = NULL;

        return 0;
}


static int message_start_transient_unit_send(
        DBusConnection *bus, DBusMessage *m, DBusError *error, DBusMessage **reply) {
        int r;

        *reply = dbus_connection_send_with_reply_and_block(bus, m, 200, error);
        return dbus_error_is_set(error) ? -1 : 0;
}

static int start_transient_service(DBusConnection *bus, char **argv, DBusError *error) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        _cleanup_free_ char *name = NULL;
        char **i;
        int r;

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, ".service");
        else
                asprintf(&name, "run-%lu.service", (unsigned long) getpid());
        if (!name)
                return log_oom();

#if 0
        r = sd_bus_message_append(m, "(sv)", "RemainAfterExit", "b", arg_remain_after_exit);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", "ExecStart");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'v', "a(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'r', "sasb");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", argv[0]);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        STRV_FOREACH (i, argv) {
                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "b", false);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;
#endif

        return message_start_transient_unit_send(bus, m, error, &reply);
}

static int start_transient_scope(DBusConnection *bus, char **argv, DBusError *error) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        _cleanup_free_ char *name = NULL;
        int r;
        uint32_t pid = getpid();
        DBusMessageIter args, aux, props, sub1, sub2, sub3, sub4;
        static const char *pids_property = "PIDs";

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, ".scope");
        else
                asprintf(&name, "run-%lu.scope", (unsigned long) getpid());
        if (!name)
                return log_oom();

        r = message_start_transient_unit_new(bus, name, &m, &args, &props);
        if (r < 0)
                return r;

        if (!dbus_message_iter_open_container(&props, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &pids_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "au", &sub3) ||
            !dbus_message_iter_open_container(&sub3, DBUS_TYPE_ARRAY, "u", &sub4) ||
            !dbus_message_iter_append_basic(&sub4, DBUS_TYPE_UINT32, &pid) ||
            !dbus_message_iter_close_container(&sub3, &sub4) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&props, &sub2))
                return log_oom();

        if (!dbus_message_iter_close_container(&args, &props))
                return log_oom();

        dbus_message_iter_open_container(&args, 'a', "(sa(sv))", &aux);
        dbus_message_iter_close_container(&args, &aux);

#if 0
        {
                const char *unique_id;
                sd_bus_get_unique_name(bus, &unique_id);
                r = sd_bus_message_append(m, "(sv)", "Controller", "s", unique_id);
                if (r < 0)
                        return r;
        }
#endif

        r = message_start_transient_unit_send(bus, m, error, &reply);
        if (r < 0)
                return r;

        execvp(argv[0], argv);
        log_error("Failed to execute: %m");
        return -errno;
}

int main(int argc, char *argv[]) {
        DBusError error;
        DBusConnection *bus = NULL;
        _cleanup_free_ char *description = NULL, *command = NULL;
        int r;

        log_parse_environment();
        log_open();

        dbus_error_init(&error);

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = find_binary(argv[optind], &command);
        if (r < 0) {
                log_error("Failed to find executable %s: %s", argv[optind], strerror(-r));
                goto finish;
        }
        argv[optind] = command;

        if (!arg_description) {
                description = strv_join(argv + optind, " ");
                if (!description) {
                        r = log_oom();
                        goto finish;
                }

                arg_description = description;
        }

        if (bus_connect(arg_user ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &bus, &private_bus, &error) < 0) {
                log_error("Failed to get D-Bus connection: %s", bus_error_message(&error));
                goto finish;
        }

        if (arg_scope)
                r = start_transient_scope(bus, argv + optind, &error);
        else
#if 0
                r = start_transient_service(bus, argv + optind, &error);
#else
        {
                log_error("%s only supports transient scopes currently.\n", program_invocation_short_name);
                r = ENOTSUP;
        }
#endif
                if (r < 0) {
                log_error("Failed start transient unit: %s", error.message ? error.message : strerror(-r));
                dbus_error_free(&error);
                goto finish;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
