#include "build.h"
#include "bus-errors.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "cjson-util.h"
#include "conf-parser.h"
#include "dbus-common.h"
#include "exit-status.h"
#include "fileio.h"
#include "initreq.h"
#include "iwctl.h"
#include "list.h"
#include "log.h"
#include "macro.h"
#include "pager.h"
#include "path-lookup.h"
#include "path-util.h"
#include "ptgroup-show.h"
#include "set.h"
#include "socket-util.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "special.h"
#include "strv.h"
#include "unit-name.h"
#include "util.h"
#include "utmp-wtmp.h"

int daemon_reload(DBusConnection *bus, char **args);

void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static void ask_password_agent_open_if_enabled(void) {

        /* Open the password agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        if (arg_scope != UNIT_FILE_SYSTEM)
                return;

        ask_password_agent_open();
}

#ifdef HAVE_LOGIND
static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        if (arg_scope != UNIT_FILE_SYSTEM)
                return;

        polkit_agent_open();
}
#endif

static int translate_bus_error_to_exit_status(int r, const DBusError *error) {
        assert(error);

        if (!dbus_error_is_set(error))
                return r;

        if (dbus_error_has_name(error, DBUS_ERROR_ACCESS_DENIED) ||
            dbus_error_has_name(error, BUS_ERROR_ONLY_BY_DEPENDENCY) ||
            dbus_error_has_name(error, BUS_ERROR_NO_ISOLATION) ||
            dbus_error_has_name(error, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE))
                return EXIT_NOPERMISSION;

        if (dbus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT))
                return EXIT_NOTINSTALLED;

        if (dbus_error_has_name(error, BUS_ERROR_JOB_TYPE_NOT_APPLICABLE) ||
            dbus_error_has_name(error, BUS_ERROR_NOT_SUPPORTED))
                return EXIT_NOTIMPLEMENTED;

        if (dbus_error_has_name(error, BUS_ERROR_LOAD_FAILED))
                return EXIT_NOTCONFIGURED;

        if (r != 0)
                return r;

        return EXIT_FAILURE;
}

void warn_wall(enum action a) {
        static const char *table[_ACTION_MAX] = {
                [ACTION_HALT] = "The system is going down for system halt NOW!",
                [ACTION_REBOOT] = "The system is going down for reboot NOW!",
                [ACTION_POWEROFF] = "The system is going down for power-off NOW!",
                [ACTION_KEXEC] = "The system is going down for kexec reboot NOW!",
                [ACTION_RESCUE] = "The system is going down to rescue mode NOW!",
                [ACTION_EMERGENCY] = "The system is going down to emergency mode NOW!",
                [ACTION_CANCEL_SHUTDOWN] = "The system shutdown has been cancelled NOW!"
        };

        if (arg_no_wall)
                return;

        if (arg_wall) {
                _cleanup_free_ char *p;

                p = strv_join(arg_wall, " ");
                if (!p) {
                        log_oom();
                        return;
                }

                if (*p) {
#ifdef Use_UTmp
                        utmp_wall(p, NULL);
#endif
                        return;
                }
        }

        if (!table[a])
                return;

#ifdef Use_UTmp
        utmp_wall(table[a], NULL);
#endif
}

bool avoid_bus(void) {

        if (running_in_chroot() > 0)
                return true;

#if 0 /* FIXME: why was that there anyway? */
        if (sd_booted() <= 0)
                return true;
#endif

        if (!isempty(arg_root))
                return true;

        if (arg_scope == UNIT_FILE_GLOBAL)
                return true;

        return false;
}

static int compare_unit_info(const void *a, const void *b) {
        const char *d1, *d2;
        const struct unit_info *u = a, *v = b;

        d1 = strrchr(u->id, '.');
        d2 = strrchr(v->id, '.');

        if (d1 && d2) {
                int r;

                r = strcasecmp(d1, d2);
                if (r != 0)
                        return r;
        }

        return strcasecmp(u->id, v->id);
}

static bool output_show_unit(const struct unit_info *u) {
        const char *dot;

        if (!strv_isempty(arg_states)) {
                if (!strv_contains(arg_states, u->load_state) && !strv_contains(arg_states, u->sub_state) &&
                    !strv_contains(arg_states, u->active_state))
                        return false;
        }

        return (!arg_types || ((dot = strrchr(u->id, '.')) && strv_find(arg_types, dot + 1))) &&
                (arg_all || !(streq(u->active_state, "inactive") || u->following[0]) || u->job_id > 0);
}

static void output_units_list(const struct unit_info *unit_infos, unsigned c) {
        unsigned id_len, max_id_len, load_len, active_len, sub_len, job_len, desc_len;
        unsigned n_shown = 0;
        const struct unit_info *u;
        int job_count = 0;

        max_id_len = strlen("UNIT");
        load_len = strlen("LOAD");
        active_len = strlen("ACTIVE");
        sub_len = strlen("SUB");
        job_len = strlen("JOB");
        desc_len = 0;

        for (u = unit_infos; u < unit_infos + c; u++) {
                if (!output_show_unit(u))
                        continue;

                max_id_len = MAX(max_id_len, strlen(u->id));
                load_len = MAX(load_len, strlen(u->load_state));
                active_len = MAX(active_len, strlen(u->active_state));
                sub_len = MAX(sub_len, strlen(u->sub_state));
                if (u->job_id != 0) {
                        job_len = MAX(job_len, strlen(u->job_type));
                        job_count++;
                }
        }

        if (!arg_full && original_stdout_is_tty) {
                unsigned basic_len;
                id_len = MIN(max_id_len, 25u);
                basic_len = 5 + id_len + 5 + active_len + sub_len;
                if (job_count)
                        basic_len += job_len + 1;
                if (basic_len < (unsigned) columns()) {
                        unsigned extra_len, incr;
                        extra_len = columns() - basic_len;
                        /* Either UNIT already got 25, or is fully satisfied.
                         * Grant up to 25 to DESC now. */
                        incr = MIN(extra_len, 25u);
                        desc_len += incr;
                        extra_len -= incr;
                        /* split the remaining space between UNIT and DESC,
                         * but do not give UNIT more than it needs. */
                        if (extra_len > 0) {
                                incr = MIN(extra_len / 2, max_id_len - id_len);
                                id_len += incr;
                                desc_len += extra_len - incr;
                        }
                }
        } else
                id_len = max_id_len;

        for (u = unit_infos; u < unit_infos + c; u++) {
                _cleanup_free_ char *e = NULL;
                const char *on_loaded, *off_loaded, *on = "";
                const char *on_active, *off_active, *off = "";

                if (!output_show_unit(u))
                        continue;

                if (!n_shown && !arg_no_legend) {
                        printf("%-*s %-*s %-*s %-*s ",
                               id_len,
                               "UNIT",
                               load_len,
                               "LOAD",
                               active_len,
                               "ACTIVE",
                               sub_len,
                               "SUB");
                        if (job_count)
                                printf("%-*s ", job_len, "JOB");
                        if (!arg_full && arg_no_pager)
                                printf("%.*s\n", desc_len, "DESCRIPTION");
                        else
                                printf("%s\n", "DESCRIPTION");
                }

                n_shown++;

                if (streq(u->load_state, "error") || streq(u->load_state, "not-found")) {
                        on_loaded = on = ansi_highlight_red();
                        off_loaded = off = ansi_highlight_off();
                } else
                        on_loaded = off_loaded = "";

                if (streq(u->active_state, "failed")) {
                        on_active = on = ansi_highlight_red();
                        off_active = off = ansi_highlight_off();
                } else
                        on_active = off_active = "";

                e = arg_full ? NULL : ellipsize(u->id, id_len, 33);

                printf("%s%-*s%s %s%-*s%s %s%-*s %-*s%s %-*s",
                       on,
                       id_len,
                       e ? e : u->id,
                       off,
                       on_loaded,
                       load_len,
                       u->load_state,
                       off_loaded,
                       on_active,
                       active_len,
                       u->active_state,
                       sub_len,
                       u->sub_state,
                       off_active,
                       job_count ? job_len + 1 : 0,
                       u->job_id ? u->job_type : "");
                if (desc_len > 0)
                        printf("%.*s\n", desc_len, u->description);
                else
                        printf("%s\n", u->description);
        }

        if (!arg_no_legend) {
                const char *on, *off;

                if (n_shown) {
                        printf("\nLOAD   = Reflects whether the unit definition was properly loaded.\n"
                               "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                               "SUB    = The low-level unit activation state, values depend on unit type.\n");
                        if (job_count)
                                printf("JOB    = Pending job for the unit.\n");
                        puts("");
                        on = ansi_highlight();
                        off = ansi_highlight_off();
                } else {
                        on = ansi_highlight_red();
                        off = ansi_highlight_off();
                }

                if (arg_all)
                        printf("%s%u loaded units listed.%s\n"
                               "To show all installed unit files use 'systemctl list-unit-files'.\n",
                               on,
                               n_shown,
                               off);
                else
                        printf("%s%u loaded units listed.%s Pass --all to see loaded but inactive units, too.\n"
                               "To show all installed unit files use 'systemctl list-unit-files'.\n",
                               on,
                               n_shown,
                               off);
        }
}

static int get_unit_list(DBusConnection *bus, DBusMessage **reply, struct unit_info **unit_infos, unsigned *c) {

        DBusMessageIter iter, sub;
        size_t size = 0;
        int r;

        assert(bus);
        assert(unit_infos);
        assert(c);

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "ListUnits",
                reply,
                NULL,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(*reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                if (!GREEDY_REALLOC(*unit_infos, size, *c + 1))
                        return log_oom();

                bus_parse_unit_info(&sub, *unit_infos + *c);
                (*c)++;

                dbus_message_iter_next(&sub);
        }

        return 0;
}

int list_units(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ struct unit_info *unit_infos = NULL;
        unsigned c = 0;
        int r;

        pager_open_if_enabled();

        r = get_unit_list(bus, &reply, &unit_infos, &c);
        if (r < 0)
                return r;

        qsort_safe(unit_infos, c, sizeof(struct unit_info), compare_unit_info);

        output_units_list(unit_infos, c);

        return 0;
}

static int get_triggered_units(DBusConnection *bus, const char *unit_path, char ***triggered) {

        const char *interface = "org.freedesktop.systemd1.Unit", *triggers_property = "Triggers";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                unit_path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &triggers_property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EBADMSG;
        }

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_recurse(&sub, &iter);
        sub = iter;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *unit;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply.");
                        return -EBADMSG;
                }

                dbus_message_iter_get_basic(&sub, &unit);
                r = strv_extend(triggered, unit);
                if (r < 0)
                        return r;

                dbus_message_iter_next(&sub);
        }

        return 0;
}

static int get_listening(DBusConnection *bus, const char *unit_path, char ***listen, unsigned *c) {
        const char *interface = "org.freedesktop.systemd1.Socket", *listen_property = "Listen";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                unit_path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &listen_property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EBADMSG;
        }

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_recurse(&sub, &iter);
        sub = iter;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                DBusMessageIter sub2;
                const char *type, *path;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EBADMSG;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0) {
                        r = strv_extend(listen, type);
                        if (r < 0)
                                return r;

                        r = strv_extend(listen, path);
                        if (r < 0)
                                return r;

                        (*c)++;
                }

                dbus_message_iter_next(&sub);
        }

        return 0;
}

struct socket_info {
        const char *id;

        char *type;
        char *path;

        /* Note: triggered is a list here, although it almost certainly
         * will always be one unit. Nevertheless, dbus API allows for multiple
         * values, so let's follow that.*/
        char **triggered;

        /* The strv above is shared. free is set only in the first one. */
        bool own_triggered;
};

static int socket_info_compare(struct socket_info *a, struct socket_info *b) {
        int o = strcmp(a->path, b->path);
        if (o == 0)
                o = strcmp(a->type, b->type);
        return o;
}

static int output_sockets_list(struct socket_info *socket_infos, unsigned cs) {
        struct socket_info *s;
        unsigned pathlen = sizeof("LISTEN") - 1, typelen = (sizeof("TYPE") - 1) * arg_show_types,
                 socklen = sizeof("UNIT") - 1, servlen = sizeof("ACTIVATES") - 1;
        const char *on, *off;

        for (s = socket_infos; s < socket_infos + cs; s++) {
                char **a;
                unsigned tmp = 0;

                socklen = MAX(socklen, strlen(s->id));
                if (arg_show_types)
                        typelen = MAX(typelen, strlen(s->type));
                pathlen = MAX(pathlen, strlen(s->path));

                STRV_FOREACH (a, s->triggered)
                        tmp += strlen(*a) + 2 * (a != s->triggered);
                servlen = MAX(servlen, tmp);
        }

        if (cs) {
                if (!arg_no_legend)
                        printf("%-*s %-*.*s%-*s %s\n",
                               pathlen,
                               "LISTEN",
                               typelen + arg_show_types,
                               typelen + arg_show_types,
                               "TYPE ",
                               socklen,
                               "UNIT",
                               "ACTIVATES");

                for (s = socket_infos; s < socket_infos + cs; s++) {
                        char **a;

                        if (arg_show_types)
                                printf("%-*s %-*s %-*s", pathlen, s->path, typelen, s->type, socklen, s->id);
                        else
                                printf("%-*s %-*s", pathlen, s->path, socklen, s->id);
                        STRV_FOREACH (a, s->triggered)
                                printf("%s %s", a == s->triggered ? "" : ",", *a);
                        printf("\n");
                }

                on = ansi_highlight();
                off = ansi_highlight_off();
                if (!arg_no_legend)
                        printf("\n");
        } else {
                on = ansi_highlight_red();
                off = ansi_highlight_off();
        }

        if (!arg_no_legend) {
                printf("%s%u sockets listed.%s\n", on, cs, off);
                if (!arg_all)
                        printf("Pass --all to see loaded but inactive sockets, too.\n");
        }

        return 0;
}

int list_sockets(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ struct unit_info *unit_infos = NULL;
        struct socket_info *socket_infos = NULL;
        const struct unit_info *u;
        struct socket_info *s;
        unsigned cu = 0, cs = 0;
        size_t size = 0;
        int r;

        pager_open_if_enabled();

        r = get_unit_list(bus, &reply, &unit_infos, &cu);
        if (r < 0)
                return r;

        for (u = unit_infos; u < unit_infos + cu; u++) {
                const char *dot;
                _cleanup_strv_free_ char **listen = NULL, **triggered = NULL;
                unsigned c = 0, i;

                if (!output_show_unit(u))
                        continue;

                if ((dot = strrchr(u->id, '.')) && !streq(dot + 1, "socket"))
                        continue;

                r = get_triggered_units(bus, u->unit_path, &triggered);
                if (r < 0)
                        goto cleanup;

                r = get_listening(bus, u->unit_path, &listen, &c);
                if (r < 0)
                        goto cleanup;

                if (!GREEDY_REALLOC(socket_infos, size, cs + c)) {
                        r = log_oom();
                        goto cleanup;
                }

                for (i = 0; i < c; i++)
                        socket_infos[cs + i] = (struct socket_info){
                                .id = u->id,
                                .type = listen[i * 2],
                                .path = listen[i * 2 + 1],
                                .triggered = triggered,
                                .own_triggered = i == 0,
                        };

                /* from this point on we will cleanup those socket_infos */
                cs += c;
                free(listen);
                listen = triggered = NULL; /* avoid cleanup */
        }

        qsort_safe(socket_infos, cs, sizeof(struct socket_info), (__compar_fn_t) socket_info_compare);

        output_sockets_list(socket_infos, cs);

cleanup:
        assert(cs == 0 || socket_infos);
        for (s = socket_infos; s < socket_infos + cs; s++) {
                free(s->type);
                free(s->path);
                if (s->own_triggered)
                        strv_free(s->triggered);
        }
        free(socket_infos);

        return 0;
}

static int compare_unit_file_list(const void *a, const void *b) {
        const char *d1, *d2;
        const UnitFileList *u = a, *v = b;

        d1 = strrchr(u->path, '.');
        d2 = strrchr(v->path, '.');

        if (d1 && d2) {
                int r;

                r = strcasecmp(d1, d2);
                if (r != 0)
                        return r;
        }

        return strcasecmp(path_get_file_name(u->path), path_get_file_name(v->path));
}

static bool output_show_unit_file(const UnitFileList *u) {
        const char *dot;

        if (!strv_isempty(arg_states)) {
                if (!strv_find(arg_states, unit_file_state_to_string(u->state)))
                        return false;
        }

        return !arg_types || ((dot = strrchr(u->path, '.')) && strv_find(arg_types, dot + 1));
}

static void output_unit_file_list(const UnitFileList *units, unsigned c) {
        unsigned max_id_len, id_cols, state_cols, n_shown = 0;
        const UnitFileList *u;

        max_id_len = sizeof("UNIT FILE") - 1;
        state_cols = sizeof("STATE") - 1;
        for (u = units; u < units + c; u++) {
                if (!output_show_unit_file(u))
                        continue;

                max_id_len = MAX(max_id_len, strlen(path_get_file_name(u->path)));
                state_cols = MAX(state_cols, strlen(unit_file_state_to_string(u->state)));
        }

        if (!arg_full) {
                unsigned basic_cols;
                id_cols = MIN(max_id_len, 25u);
                basic_cols = 1 + id_cols + state_cols;
                if (basic_cols < (unsigned) columns())
                        id_cols += MIN(columns() - basic_cols, max_id_len - id_cols);
        } else
                id_cols = max_id_len;

        if (!arg_no_legend)
                printf("%-*s %-*s\n", id_cols, "UNIT FILE", state_cols, "STATE");

        for (u = units; u < units + c; u++) {
                _cleanup_free_ char *e = NULL;
                const char *on, *off;
                const char *id;

                if (!output_show_unit_file(u))
                        continue;

                n_shown++;

                if (u->state == UNIT_FILE_MASKED || u->state == UNIT_FILE_MASKED_RUNTIME ||
                    u->state == UNIT_FILE_DISABLED || u->state == UNIT_FILE_INVALID) {
                        on = ansi_highlight_red();
                        off = ansi_highlight_off();
                } else if (u->state == UNIT_FILE_ENABLED) {
                        on = ansi_highlight_green();
                        off = ansi_highlight_off();
                } else
                        on = off = "";

                id = path_get_file_name(u->path);

                e = arg_full ? NULL : ellipsize(id, id_cols, 33);

                printf("%-*s %s%-*s%s\n",
                       id_cols,
                       e ? e : id,
                       on,
                       state_cols,
                       unit_file_state_to_string(u->state),
                       off);
        }

        if (!arg_no_legend)
                printf("\n%u unit files listed.\n", n_shown);
}

int list_unit_files(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ UnitFileList *units = NULL;
        DBusMessageIter iter, sub, sub2;
        unsigned c = 0, n_units = 0;
        int r;

        pager_open_if_enabled();

        if (avoid_bus()) {
                Hashmap *h;
                UnitFileList *u;
                Iterator i;

                h = hashmap_new(string_hash_func, string_compare_func);
                if (!h)
                        return log_oom();

                r = unit_file_get_list(arg_scope, arg_root, h);
                if (r < 0) {
                        unit_file_list_free(h);
                        log_error("Failed to get unit file list: %s", strerror(-r));
                        return r;
                }

                n_units = hashmap_size(h);

                if (n_units == 0)
                        return 0;

                units = new (UnitFileList, n_units);
                if (!units) {
                        unit_file_list_free(h);
                        return log_oom();
                }

                HASHMAP_FOREACH (u, h, i) {
                        memcpy(units + c++, u, sizeof(UnitFileList));
                        free(u);
                }

                hashmap_free(h);
        } else {
                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnitFiles",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;

                if (!dbus_message_iter_init(reply, &iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&iter, &sub);

                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                        UnitFileList *u;
                        const char *state;

                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT);

                        if (c >= n_units) {
                                UnitFileList *w;

                                n_units = MAX(2 * c, 16u);
                                w = realloc(units, sizeof(struct UnitFileList) * n_units);
                                if (!w)
                                        return log_oom();

                                units = w;
                        }

                        u = units + c;

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &state, false) < 0) {
                                log_error("Failed to parse reply.");
                                return -EIO;
                        }

                        u->state = unit_file_state_from_string(state);

                        dbus_message_iter_next(&sub);
                        c++;
                }
        }

        if (c > 0) {
                qsort(units, c, sizeof(UnitFileList), compare_unit_file_list);
                output_unit_file_list(units, c);
        }

        return 0;
}

static int list_dependencies_print(const char *name, int level, unsigned int branches, bool last) {
        int i;
        _cleanup_free_ char *n = NULL;
        size_t len = 0;
        size_t max_len = MAX(columns(), 20u);

        if (!arg_plain) {
                for (i = level - 1; i >= 0; i--) {
                        len += 2;
                        if (len > max_len - 3 && !arg_full) {
                                printf("%s...\n", max_len % 2 ? "" : " ");
                                return 0;
                        }
                        printf("%s",
                               draw_special_char(branches & (1 << i) ? DRAW_TREE_VERT : DRAW_TREE_SPACE));
                }
                len += 2;
                if (len > max_len - 3 && !arg_full) {
                        printf("%s...\n", max_len % 2 ? "" : " ");
                        return 0;
                }
                printf("%s", draw_special_char(last ? DRAW_TREE_RIGHT : DRAW_TREE_BRANCH));
        }

        if (arg_full) {
                printf("%s\n", name);
                return 0;
        }

        n = ellipsize(name, max_len - len, 100);
        if (!n)
                return log_oom();

        printf("%s\n", n);
        return 0;
}

static int list_dependencies_get_dependencies(DBusConnection *bus, const char *name, char ***deps) {
        static const char *dependencies[] = {
                [DEPENDENCY_FORWARD] =
                        "Requires\0"
                        "RequiresOverridable\0"
                        "Requisite\0"
                        "RequisiteOverridable\0"
                        "Wants\0",
                [DEPENDENCY_REVERSE] =
                        "RequiredBy\0"
                        "RequiredByOverridable\0"
                        "WantedBy\0"
                        "PartOf\0",
                [DEPENDENCY_AFTER] = "After\0",
                [DEPENDENCY_BEFORE] = "Before\0",
        };

        _cleanup_free_ char *path;
        const char *interface = "org.freedesktop.systemd1.Unit";

        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2, sub3;

        int r = 0;
        char **ret = NULL;

        assert(bus);
        assert(name);
        assert(deps);

        path = unit_dbus_path_from_name(name);
        if (path == NULL) {
                r = -EINVAL;
                goto finish;
        }

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_INVALID);
        if (r < 0)
                goto finish;

        if (!dbus_message_iter_init(reply, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY) {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *prop;

                assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_DICT_ENTRY);
                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &prop, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);
                dbus_message_iter_next(&sub);

                assert(arg_dependency < ELEMENTSOF(dependencies));
                if (!nulstr_contains(dependencies[arg_dependency], prop))
                        continue;

                if (dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_ARRAY) {
                        if (dbus_message_iter_get_element_type(&sub3) == DBUS_TYPE_STRING) {
                                DBusMessageIter sub4;
                                dbus_message_iter_recurse(&sub3, &sub4);

                                while (dbus_message_iter_get_arg_type(&sub4) != DBUS_TYPE_INVALID) {
                                        const char *s;

                                        assert(dbus_message_iter_get_arg_type(&sub4) == DBUS_TYPE_STRING);
                                        dbus_message_iter_get_basic(&sub4, &s);

                                        r = strv_extend(&ret, s);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        dbus_message_iter_next(&sub4);
                                }
                        }
                }
        }
finish:
        if (r < 0)
                strv_free(ret);
        else
                *deps = ret;
        return r;
}

static int list_dependencies_compare(const void *_a, const void *_b) {
        const char **a = (const char **) _a, **b = (const char **) _b;
        if (unit_name_to_type(*a) == UNIT_TARGET && unit_name_to_type(*b) != UNIT_TARGET)
                return 1;
        if (unit_name_to_type(*a) != UNIT_TARGET && unit_name_to_type(*b) == UNIT_TARGET)
                return -1;
        return strcasecmp(*a, *b);
}

static int list_dependencies_one(
        DBusConnection *bus, const char *name, int level, char ***units, unsigned int branches) {
        _cleanup_strv_free_ char **deps = NULL, **u;
        char **c;
        int r = 0;

        u = strv_append(*units, name);
        if (!u)
                return log_oom();

        r = list_dependencies_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        qsort_safe(deps, strv_length(deps), sizeof(char *), list_dependencies_compare);

        STRV_FOREACH (c, deps) {
                if (strv_contains(u, *c)) {
                        if (!arg_plain) {
                                r = list_dependencies_print(
                                        "...", level + 1, (branches << 1) | (c[1] == NULL ? 0 : 1), 1);
                                if (r < 0)
                                        return r;
                        }
                        continue;
                }

                r = list_dependencies_print(*c, level, branches, c[1] == NULL);
                if (r < 0)
                        return r;

                if (arg_all || unit_name_to_type(*c) == UNIT_TARGET) {
                        r = list_dependencies_one(
                                bus, *c, level + 1, &u, (branches << 1) | (c[1] == NULL ? 0 : 1));
                        if (r < 0)
                                return r;
                }
        }
        if (arg_plain) {
                strv_free(*units);
                *units = u;
                u = NULL;
        }
        return 0;
}

int list_dependencies(DBusConnection *bus, char **args) {
        _cleanup_free_ char *unit = NULL;
        _cleanup_strv_free_ char **units = NULL;
        const char *u;

        assert(bus);

        if (args[1]) {
                unit = unit_name_mangle(args[1]);
                if (!unit)
                        return log_oom();
                u = unit;
        } else
                u = SPECIAL_DEFAULT_TARGET;

        pager_open_if_enabled();

        puts(u);

        return list_dependencies_one(bus, u, 0, &units, 0);
}

int get_default(DBusConnection *bus, char **args) {
        char *path = NULL;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        _cleanup_dbus_error_free_ DBusError error;

        dbus_error_init(&error);

        if (!bus || avoid_bus()) {
                r = unit_file_get_default(arg_scope, arg_root, &path);

                if (r < 0) {
                        log_error("Operation failed: %s", strerror(-r));
                        goto finish;
                }

                r = 0;
        } else {
                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "GetDefaultTarget",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);

                if (r < 0) {
                        log_error("Operation failed: %s", strerror(-r));
                        goto finish;
                }

                if (!dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        dbus_error_free(&error);
                        return -EIO;
                }
        }

        if (path)
                printf("%s\n", path);

finish:
        if ((!bus || avoid_bus()) && path)
                free(path);

        return r;
}

struct job_info {
        uint32_t id;
        char *name, *type, *state;
};

static void list_jobs_print(struct job_info *jobs, size_t n) {
        size_t i;
        struct job_info *j;
        const char *on, *off;
        bool shorten = false;

        assert(n == 0 || jobs);

        if (n == 0) {
                on = ansi_highlight_green();
                off = ansi_highlight_off();

                printf("%sNo jobs running.%s\n", on, off);
                return;
        }

        pager_open_if_enabled();

        {
                /* JOB UNIT TYPE STATE */
                unsigned l0 = 3, l1 = 4, l2 = 4, l3 = 5;

                for (i = 0, j = jobs; i < n; i++, j++) {
                        assert(j->name && j->type && j->state);
                        l0 = MAX(l0, DECIMAL_STR_WIDTH(j->id));
                        l1 = MAX(l1, strlen(j->name));
                        l2 = MAX(l2, strlen(j->type));
                        l3 = MAX(l3, strlen(j->state));
                }

                if (!arg_full && l0 + 1 + l1 + l2 + 1 + l3 > columns()) {
                        l1 = MAX(33u, columns() - l0 - l2 - l3 - 3);
                        shorten = true;
                }

                if (on_tty())
                        printf("%*s %-*s %-*s %-*s\n", l0, "JOB", l1, "UNIT", l2, "TYPE", l3, "STATE");

                for (i = 0, j = jobs; i < n; i++, j++) {
                        _cleanup_free_ char *e = NULL;

                        if (streq(j->state, "running")) {
                                on = ansi_highlight();
                                off = ansi_highlight_off();
                        } else
                                on = off = "";

                        e = shorten ? ellipsize(j->name, l1, 33) : NULL;
                        printf("%*u %s%-*s%s %-*s %s%-*s%s\n",
                               l0,
                               j->id,
                               on,
                               l1,
                               e ? e : j->name,
                               off,
                               l2,
                               j->type,
                               on,
                               l3,
                               j->state,
                               off);
                }
        }

        on = ansi_highlight();
        off = ansi_highlight_off();

        if (on_tty())
                printf("\n%s%zu jobs listed%s.\n", on, n, off);
}

int list_jobs(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2;
        int r;
        struct job_info *jobs = NULL;
        size_t size = 0, used = 0;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "ListJobs",
                &reply,
                NULL,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name, *type, *state, *job_path, *unit_path;
                uint32_t id;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (!GREEDY_REALLOC(jobs, size, used + 1)) {
                        r = log_oom();
                        goto finish;
                }

                jobs[used++] = (struct job_info){ id, strdup(name), strdup(type), strdup(state) };
                if (!jobs[used - 1].name || !jobs[used - 1].type || !jobs[used - 1].state) {
                        r = log_oom();
                        goto finish;
                }

                dbus_message_iter_next(&sub);
        }

        list_jobs_print(jobs, used);

finish:
        while (used--) {
                free(jobs[used].name);
                free(jobs[used].type);
                free(jobs[used].state);
        }
        free(jobs);

        return r;
}

int cancel_job(DBusConnection *bus, char **args) {
        char **name;

        assert(args);

        if (strv_length(args) <= 1)
                return daemon_reload(bus, args);

        STRV_FOREACH (name, args + 1) {
                uint32_t id;
                int r;

                r = safe_atou32(*name, &id);
                if (r < 0) {
                        log_error("Failed to parse job id: %s", strerror(-r));
                        return r;
                }

                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "CancelJob",
                        NULL,
                        NULL,
                        DBUS_TYPE_UINT32,
                        &id,
                        DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int need_daemon_reload(DBusConnection *bus, const char *unit) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_dbus_error_free_ DBusError error;
        dbus_bool_t b = FALSE;
        DBusMessageIter iter, sub;
        const char *interface = "org.freedesktop.systemd1.Unit", *property = "NeedDaemonReload", *path;
        _cleanup_free_ char *n = NULL;
        int r;

        dbus_error_init(&error);

        /* We ignore all errors here, since this is used to show a warning only */

        n = unit_name_mangle(unit);
        if (!n)
                return log_oom();

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &reply,
                &error,
                DBUS_TYPE_STRING,
                &n,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
                return -EIO;

        dbus_message_unref(reply);
        reply = NULL;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                &error,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
                return -EIO;

        dbus_message_iter_recurse(&iter, &sub);
        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
                return -EIO;

        dbus_message_iter_get_basic(&sub, &b);
        return b;
}

typedef struct WaitData {
        Set *set;

        char *name;
        char *result;
} WaitData;

static DBusHandlerResult wait_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        _cleanup_dbus_error_free_ DBusError error;
        WaitData *d = data;

        dbus_error_init(&error);

        assert(connection);
        assert(message);
        assert(d);

        log_debug(
                "Got D-Bus request: %s.%s() on %s",
                dbus_message_get_interface(message),
                dbus_message_get_member(message),
                dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");
                dbus_connection_close(connection);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                uint32_t id;
                const char *path, *result, *unit;
                char *r;

                if (dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_UINT32,
                            &id,
                            DBUS_TYPE_OBJECT_PATH,
                            &path,
                            DBUS_TYPE_STRING,
                            &unit,
                            DBUS_TYPE_STRING,
                            &result,
                            DBUS_TYPE_INVALID)) {

                        r = set_remove(d->set, (char *) path);
                        if (!r)
                                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

                        free(r);

                        if (!isempty(result))
                                d->result = strdup(result);

                        if (!isempty(unit))
                                d->name = strdup(unit);

                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
                }
#ifndef NOLEGACY
                dbus_error_free(&error);
                if (dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_UINT32,
                            &id,
                            DBUS_TYPE_OBJECT_PATH,
                            &path,
                            DBUS_TYPE_STRING,
                            &result,
                            DBUS_TYPE_INVALID)) {
                        /* Compatibility with older systemd versions <
                         * 183 during upgrades. This should be dropped
                         * one day. */
                        r = set_remove(d->set, (char *) path);
                        if (!r)
                                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

                        free(r);

                        if (*result)
                                d->result = strdup(result);

                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
                }
#endif

                log_error("Failed to parse message: %s", bus_error_message(&error));
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int enable_wait_for_jobs(DBusConnection *bus) {
        DBusError error;

        assert(bus);

        if (private_bus)
                return 0;

        dbus_error_init(&error);
        dbus_bus_add_match(
                bus,
                "type='signal',"
                "sender='org.freedesktop.systemd1',"
                "interface='org.freedesktop.systemd1.Manager',"
                "member='JobRemoved',"
                "path='/org/freedesktop/systemd1'",
                &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return -EIO;
        }

        /* This is slightly dirty, since we don't undo the match registrations. */
        return 0;
}

static int wait_for_jobs(DBusConnection *bus, Set *s) {
        int r = 0;
        WaitData d = { .set = s };

        assert(bus);
        assert(s);

        if (!dbus_connection_add_filter(bus, wait_filter, &d, NULL))
                return log_oom();

        while (!set_isempty(s)) {

                if (!dbus_connection_read_write_dispatch(bus, -1)) {
                        log_error("Disconnected from bus.");
                        return -ECONNREFUSED;
                }

                if (!d.result)
                        goto free_name;

                if (!arg_quiet) {
                        if (streq(d.result, "timeout"))
                                log_error("Job for %s timed out.", strna(d.name));
                        else if (streq(d.result, "canceled"))
                                log_error("Job for %s canceled.", strna(d.name));
                        else if (streq(d.result, "dependency"))
                                log_error(
                                        "A dependency job for %s failed. See 'journalctl -xn' for details.",
                                        strna(d.name));
                        else if (!streq(d.result, "done") && !streq(d.result, "skipped"))
                                log_error(
                                        "Job for %s failed. See 'systemctl status %s' and 'journalctl -xn' for details.",
                                        strna(d.name),
                                        strna(d.name));
                }

                if (streq_ptr(d.result, "timeout"))
                        r = -ETIME;
                else if (streq_ptr(d.result, "canceled"))
                        r = -ECANCELED;
                else if (!streq_ptr(d.result, "done") && !streq_ptr(d.result, "skipped"))
                        r = -EIO;

                free(d.result);
                d.result = NULL;

        free_name:
                free(d.name);
                d.name = NULL;
        }

        dbus_connection_remove_filter(bus, wait_filter, &d);
        return r;
}

static int check_one_unit(DBusConnection *bus, const char *name, char **check_states, bool quiet) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *n = NULL;
        DBusMessageIter iter, sub;
        const char *interface = "org.freedesktop.systemd1.Unit", *property = "ActiveState";
        const char *state, *path;
        DBusError error;
        int r;

        assert(name);

        dbus_error_init(&error);

        n = unit_name_mangle(name);
        if (!n)
                return log_oom();

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &reply,
                &error,
                DBUS_TYPE_STRING,
                &n,
                DBUS_TYPE_INVALID);
        if (r < 0) {
                dbus_error_free(&error);

                if (!quiet)
                        puts("unknown");
                return 0;
        }

        if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_unref(reply);
        reply = NULL;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &property,
                DBUS_TYPE_INVALID);
        if (r < 0) {
                if (!quiet)
                        puts("unknown");
                return 0;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return r;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return r;
        }

        dbus_message_iter_get_basic(&sub, &state);

        if (!quiet)
                puts(state);

        return strv_find(check_states, state) ? 1 : 0;
}

static void check_triggering_units(DBusConnection *bus, const char *unit_name) {

        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        const char *interface = "org.freedesktop.systemd1.Unit", *load_state_property = "LoadState",
                   *triggered_by_property = "TriggeredBy", *state;
        _cleanup_free_ char *unit_path = NULL, *n = NULL;
        bool print_warning_label = true;
        int r;

        n = unit_name_mangle(unit_name);
        if (!n) {
                log_oom();
                return;
        }

        unit_path = unit_dbus_path_from_name(n);
        if (!unit_path) {
                log_oom();
                return;
        }

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                unit_path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &load_state_property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return;
        }

        dbus_message_iter_get_basic(&sub, &state);

        if (streq(state, "masked"))
                return;

        dbus_message_unref(reply);
        reply = NULL;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                unit_path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &triggered_by_property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return;
        }

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_recurse(&sub, &iter);
        sub = iter;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *const check_states[] = { "active", "reloading", NULL };
                const char *service_trigger;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply.");
                        return;
                }

                dbus_message_iter_get_basic(&sub, &service_trigger);

                r = check_one_unit(bus, service_trigger, (char **) check_states, true);
                if (r < 0)
                        return;
                if (r > 0) {
                        if (print_warning_label) {
                                log_warning(
                                        "Warning: Stopping %s, but it can still be activated by:", unit_name);
                                print_warning_label = false;
                        }

                        log_warning("  %s", service_trigger);
                }

                dbus_message_iter_next(&sub);
        }
}

static int start_unit_one(
        DBusConnection *bus, const char *method, const char *name, const char *mode, DBusError *error, Set *s) {

        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *n;
        const char *path;
        int r;

        assert(method);
        assert(name);
        assert(mode);
        assert(error);

        n = unit_name_mangle(name);
        if (!n)
                return log_oom();

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                method,
                &reply,
                error,
                DBUS_TYPE_STRING,
                &n,
                DBUS_TYPE_STRING,
                &mode,
                DBUS_TYPE_INVALID);
        if (r) {
                if (r == -ENOENT && arg_action != ACTION_SYSTEMCTL)
                        /* There's always a fallback possible for
                         * legacy actions. */
                        r = -EADDRNOTAVAIL;
                else
                        log_error("Failed to issue method call: %s", bus_error_message(error));

                return r;
        }

        if (!dbus_message_get_args(reply, error, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(error));
                return -EIO;
        }

        if (need_daemon_reload(bus, n) > 0)
                log_warning(
                        "Warning: Unit file of %s changed on disk, 'systemctl %sdaemon-reload' recommended.",
                        n,
                        arg_scope == UNIT_FILE_SYSTEM ? "" : "--user ");

        if (s) {
                char *p;

                p = strdup(path);
                if (!p)
                        return log_oom();

                r = set_consume(s, p);
                if (r < 0) {
                        log_error("Failed to add path to set.");
                        return r;
                }
        }

        return 0;
}

static const struct {
        const char *target;
        const char *verb;
        const char *mode;
} action_table[_ACTION_MAX] = {
        [ACTION_HALT] = { SPECIAL_HALT_TARGET, "halt", "replace-irreversibly" },
        [ACTION_POWEROFF] = { SPECIAL_POWEROFF_TARGET, "poweroff", "replace-irreversibly" },
        [ACTION_REBOOT] = { SPECIAL_REBOOT_TARGET, "reboot", "replace-irreversibly" },
        [ACTION_KEXEC] = { SPECIAL_KEXEC_TARGET, "kexec", "replace-irreversibly" },
        [ACTION_RUNLEVEL2] = { SPECIAL_RUNLEVEL2_TARGET, NULL, "isolate" },
        [ACTION_RUNLEVEL3] = { SPECIAL_RUNLEVEL3_TARGET, NULL, "isolate" },
        [ACTION_RUNLEVEL4] = { SPECIAL_RUNLEVEL4_TARGET, NULL, "isolate" },
        [ACTION_RUNLEVEL5] = { SPECIAL_RUNLEVEL5_TARGET, NULL, "isolate" },
        [ACTION_RESCUE] = { SPECIAL_RESCUE_TARGET, "rescue", "isolate" },
        [ACTION_EMERGENCY] = { SPECIAL_EMERGENCY_TARGET, "emergency", "isolate" },
        [ACTION_DEFAULT] = { SPECIAL_DEFAULT_TARGET, "default", "isolate" },
        [ACTION_EXIT] = { SPECIAL_EXIT_TARGET, "exit", "replace-irreversibly" },
        [ACTION_SUSPEND] = { SPECIAL_SUSPEND_TARGET, "suspend", "replace-irreversibly" },
        [ACTION_HIBERNATE] = { SPECIAL_HIBERNATE_TARGET, "hibernate", "replace-irreversibly" },
        [ACTION_HYBRID_SLEEP] = { SPECIAL_HYBRID_SLEEP_TARGET, "hybrid-sleep", "replace-irreversibly" },
};

static enum action verb_to_action(const char *verb) {
        enum action i;

        for (i = ACTION_INVALID; i < _ACTION_MAX; i++)
                if (action_table[i].verb && streq(verb, action_table[i].verb))
                        return i;
        return ACTION_INVALID;
}

int start_unit(DBusConnection *bus, char **args) {

        int r, ret = 0;
        const char *method, *mode, *one_name;
        _cleanup_set_free_free_ Set *s = NULL;
        _cleanup_dbus_error_free_ DBusError error;
        char **name;

        dbus_error_init(&error);

        assert(bus);

        ask_password_agent_open_if_enabled();

        if (arg_action == ACTION_SYSTEMCTL) {
                enum action action;
                method = streq(args[0], "stop") || streq(args[0], "condstop") ? "StopUnit" :
                        streq(args[0], "reload")                              ? "ReloadUnit" :
                        streq(args[0], "restart")                             ? "RestartUnit" :

                        streq(args[0], "try-restart") || streq(args[0], "condrestart") ? "TryRestartUnit" :

                        streq(args[0], "reload-or-restart") ? "ReloadOrRestartUnit" :

                        streq(args[0], "reload-or-try-restart") || streq(args[0], "condreload") ||

                                streq(args[0], "force-reload") ?
                                                              "ReloadOrTryRestartUnit" :
                                                              "StartUnit";
                action = verb_to_action(args[0]);

                mode = streq(args[0], "isolate") ? "isolate" : action_table[action].mode ?: arg_job_mode;

                one_name = action_table[action].target;

        } else {
                assert(arg_action < ELEMENTSOF(action_table));
                assert(action_table[arg_action].target);

                method = "StartUnit";

                mode = action_table[arg_action].mode;
                one_name = action_table[arg_action].target;
        }

        if (!arg_no_block) {
                ret = enable_wait_for_jobs(bus);
                if (ret < 0) {
                        log_error("Could not watch jobs: %s", strerror(-ret));
                        return ret;
                }

                s = set_new(string_hash_func, string_compare_func);
                if (!s)
                        return log_oom();
        }

        if (one_name) {
                ret = start_unit_one(bus, method, one_name, mode, &error, s);
                if (ret < 0)
                        ret = translate_bus_error_to_exit_status(ret, &error);
        } else {
                STRV_FOREACH (name, args + 1) {
                        r = start_unit_one(bus, method, *name, mode, &error, s);
                        if (r < 0) {
                                ret = translate_bus_error_to_exit_status(r, &error);
                                dbus_error_free(&error);
                        }
                }
        }

        if (!arg_no_block) {
                r = wait_for_jobs(bus, s);
                if (r < 0)
                        return r;

                /* When stopping units, warn if they can still be triggered by
                 * another active unit (socket, path, timer) */
                if (!arg_quiet && streq(method, "StopUnit")) {
                        if (one_name)
                                check_triggering_units(bus, one_name);
                        else
                                STRV_FOREACH (name, args + 1)
                                        check_triggering_units(bus, *name);
                }
        }

        return ret;
}

/* Ask systemd-logind, which might grant access to unprivileged users
 * through PolicyKit */
int reboot_with_logind(DBusConnection *bus, enum action a) {
#ifdef HAVE_LOGIND
        const char *method;
        dbus_bool_t interactive = true;

        if (!bus)
                return -EIO;

        polkit_agent_open_if_enabled();

        switch (a) {

        case ACTION_REBOOT:
                method = "Reboot";
                break;

        case ACTION_POWEROFF:
                method = "PowerOff";
                break;

        case ACTION_SUSPEND:
                method = "Suspend";
                break;

        case ACTION_HIBERNATE:
                method = "Hibernate";
                break;

        case ACTION_HYBRID_SLEEP:
                method = "HybridSleep";
                break;

        default:
                return -EINVAL;
        }

        return bus_method_call_with_reply(
                bus,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                method,
                NULL,
                NULL,
                DBUS_TYPE_BOOLEAN,
                &interactive,
                DBUS_TYPE_INVALID);
#else
        return -ENOSYS;
#endif
}

int check_inhibitors(DBusConnection *bus, enum action a) {
#ifdef HAVE_LOGIND
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2;
        int r;
        unsigned c = 0;
        _cleanup_strv_free_ char **sessions = NULL;
        char **s;

        if (!bus)
                return 0;

        if (arg_ignore_inhibitors || arg_force > 0)
                return 0;

        if (arg_when > 0)
                return 0;

        if (geteuid() == 0)
                return 0;

        if (!on_tty())
                return 0;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "ListInhibitors",
                &reply,
                NULL,
                DBUS_TYPE_INVALID);
        if (r < 0)
                /* If logind is not around, then there are no inhibitors... */
                return 0;

        if (!dbus_message_iter_init(reply, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);
        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *what, *who, *why, *mode;
                uint32_t uid, pid;
                _cleanup_strv_free_ char **sv = NULL;
                _cleanup_free_ char *comm = NULL, *user = NULL;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &what, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &who, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &why, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &mode, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &pid, false) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                if (!streq(mode, "block"))
                        goto next;

                sv = strv_split(what, ":");
                if (!sv)
                        return log_oom();

                if (!strv_contains(
                            sv,
                            a == ACTION_HALT || a == ACTION_POWEROFF || a == ACTION_REBOOT || a == ACTION_KEXEC ?
                                    "shutdown" :
                                    "sleep"))
                        goto next;

                get_process_comm(pid, &comm);
                user = uid_to_name(uid);
                log_warning(
                        "Operation inhibited by \"%s\" (PID %lu \"%s\", user %s), reason is \"%s\".",
                        who,
                        (unsigned long) pid,
                        strna(comm),
                        strna(user),
                        why);
                c++;

        next:
                dbus_message_iter_next(&sub);
        }

        dbus_message_iter_recurse(&iter, &sub);

        /* Check for current sessions */
        sd_get_sessions(&sessions);
        STRV_FOREACH (s, sessions) {
                uid_t uid;
                _cleanup_free_ char *type = NULL, *tty = NULL, *seat = NULL, *user = NULL, *service = NULL,
                                    *class = NULL;

                if (sd_session_get_uid(*s, &uid) < 0 || uid == getuid())
                        continue;

                if (sd_session_get_class(*s, &class) < 0 || !streq(class, "user"))
                        continue;

                if (sd_session_get_type(*s, &type) < 0 || (!streq(type, "x11") && !streq(type, "tty")))
                        continue;

                sd_session_get_tty(*s, &tty);
                sd_session_get_seat(*s, &seat);
                sd_session_get_service(*s, &service);
                user = uid_to_name(uid);

                log_warning(
                        "User %s is logged in on %s.",
                        strna(user),
                        isempty(tty) ? (isempty(seat) ? strna(service) : seat) : tty);
                c++;
        }

        if (c <= 0)
                return 0;

        log_error(
                "Please retry operation after closing inhibitors and logging out other users.\nAlternatively, ignore inhibitors and users with 'systemctl %s -i'.",
                action_table[a].verb);

        return -EPERM;
#else
        return 0;
#endif
}

int start_special(DBusConnection *bus, char **args) {
        enum action a;
        int r;

        assert(args);

        a = verb_to_action(args[0]);

        r = check_inhibitors(bus, a);
        if (r < 0)
                return r;

        if (arg_force >= 2 && geteuid() != 0) {
                log_error("Must be root.");
                return -EPERM;
        }

        if (arg_force >= 2 && (a == ACTION_HALT || a == ACTION_POWEROFF || a == ACTION_REBOOT))
                halt_now(a);

        if (arg_force >= 1 &&
            (a == ACTION_HALT || a == ACTION_POWEROFF || a == ACTION_REBOOT || a == ACTION_KEXEC ||
             a == ACTION_EXIT))
                return daemon_reload(bus, args);

        /* first try logind, to allow authentication with polkit */
        if (geteuid() != 0 &&
            (a == ACTION_POWEROFF || a == ACTION_REBOOT || a == ACTION_SUSPEND || a == ACTION_HIBERNATE ||
             a == ACTION_HYBRID_SLEEP)) {
                r = reboot_with_logind(bus, a);
                if (r >= 0)
                        return r;
        }

        r = start_unit(bus, args);
        if (r == EXIT_SUCCESS)
                warn_wall(a);

        return r;
}

int check_unit_active(DBusConnection *bus, char **args) {
        const char *const check_states[] = { "active", "reloading", NULL };

        char **name;
        int r = 3; /* According to LSB: "program is not running" */

        assert(bus);
        assert(args);

        STRV_FOREACH (name, args + 1) {
                int state;

                state = check_one_unit(bus, *name, (char **) check_states, arg_quiet);
                if (state < 0)
                        return state;
                if (state > 0)
                        r = 0;
        }

        return r;
}

int check_unit_failed(DBusConnection *bus, char **args) {
        const char *const check_states[] = { "failed", NULL };

        char **name;
        int r = 1;

        assert(bus);
        assert(args);

        STRV_FOREACH (name, args + 1) {
                int state;

                state = check_one_unit(bus, *name, (char **) check_states, arg_quiet);
                if (state < 0)
                        return state;
                if (state > 0)
                        r = 0;
        }

        return r;
}

int kill_unit(DBusConnection *bus, char **args) {
        char **name;
        int r = 0;

        assert(bus);
        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        STRV_FOREACH (name, args + 1) {
                _cleanup_free_ char *n = NULL;

                n = unit_name_mangle(*name);
                if (!n)
                        return log_oom();

                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING,
                        &n,
                        DBUS_TYPE_STRING,
                        &arg_kill_who,
                        DBUS_TYPE_INT32,
                        &arg_signal,
                        DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;
        }
        return 0;
}

typedef struct ExecStatusInfo {
        char *name;

        char *path;
        char **argv;

        bool ignore;

        usec_t start_timestamp;
        usec_t exit_timestamp;
        pid_t pid;
        int code;
        int status;

        IWLIST_FIELDS(struct ExecStatusInfo, exec);
} ExecStatusInfo;

static void exec_status_info_free(ExecStatusInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->argv);
        free(i);
}

static int exec_status_info_deserialize(DBusMessageIter *sub, ExecStatusInfo *i) {
        uint64_t start_timestamp, exit_timestamp, start_timestamp_monotonic, exit_timestamp_monotonic;
        DBusMessageIter sub2, sub3;
        const char *path;
        unsigned n;
        uint32_t pid;
        int32_t code, status;
        dbus_bool_t ignore;

        assert(i);
        assert(i);

        if (dbus_message_iter_get_arg_type(sub) != DBUS_TYPE_STRUCT)
                return -EIO;

        dbus_message_iter_recurse(sub, &sub2);

        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0)
                return -EIO;

        i->path = strdup(path);
        if (!i->path)
                return -ENOMEM;

        if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&sub2) != DBUS_TYPE_STRING)
                return -EIO;

        n = 0;
        dbus_message_iter_recurse(&sub2, &sub3);
        while (dbus_message_iter_get_arg_type(&sub3) != DBUS_TYPE_INVALID) {
                assert(dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_STRING);
                dbus_message_iter_next(&sub3);
                n++;
        }

        i->argv = new0(char *, n + 1);
        if (!i->argv)
                return -ENOMEM;

        n = 0;
        dbus_message_iter_recurse(&sub2, &sub3);
        while (dbus_message_iter_get_arg_type(&sub3) != DBUS_TYPE_INVALID) {
                const char *s;

                assert(dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_STRING);
                dbus_message_iter_get_basic(&sub3, &s);
                dbus_message_iter_next(&sub3);

                i->argv[n] = strdup(s);
                if (!i->argv[n])
                        return -ENOMEM;

                n++;
        }

        if (!dbus_message_iter_next(&sub2) ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &ignore, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &start_timestamp, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &start_timestamp_monotonic, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &exit_timestamp, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &exit_timestamp_monotonic, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &pid, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_INT32, &code, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_INT32, &status, false) < 0)
                return -EIO;

        i->ignore = ignore;
        i->start_timestamp = (usec_t) start_timestamp;
        i->exit_timestamp = (usec_t) exit_timestamp;
        i->pid = (pid_t) pid;
        i->code = code;
        i->status = status;

        return 0;
}

typedef struct UnitStatusInfo {
        const char *id;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *unit_file_state;

        const char *description;
        const char *following;

        char **documentation;

        const char *fragment_path;
        const char *source_path;
        /* cgroup path */
        const char *control_group;
        /* ptgroup JSON object */
        cJSON *ptgroup;

        char **dropin_paths;

        const char *load_error;
        const char *result;

        usec_t inactive_exit_timestamp;
        usec_t inactive_exit_timestamp_monotonic;
        usec_t active_enter_timestamp;
        usec_t active_exit_timestamp;
        usec_t inactive_enter_timestamp;

        bool need_daemon_reload;

        /* Service */
        pid_t main_pid;
        pid_t control_pid;
        const char *status_text;
        const char *pid_file;
        bool running : 1;

        usec_t start_timestamp;
        usec_t exit_timestamp;

        int exit_code, exit_status;

        usec_t condition_timestamp;
        bool condition_result;
        bool failed_condition_trigger;
        bool failed_condition_negate;
        const char *failed_condition;
        const char *failed_condition_param;

        /* Socket */
        unsigned n_accepted;
        unsigned n_connections;
        bool accept;

        /* Pairs of type, path */
        char **listen;

        /* Device */
        const char *sysfs_path;

        /* Mount, Automount */
        const char *where;

        /* Swap */
        const char *what;

        IWLIST_HEAD(ExecStatusInfo, exec);
} UnitStatusInfo;

static void print_status_info(UnitStatusInfo *i, bool *ellipsized) {
        ExecStatusInfo *p;
        const char *on, *off, *ss;
        usec_t timestamp;
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        const char *path;
        int flags = arg_all * OUTPUT_SHOW_ALL | (!on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                on_tty() * OUTPUT_COLOR | !arg_quiet * OUTPUT_WARN_CUTOFF | arg_full * OUTPUT_FULL_WIDTH;
        char **t, **t2;

        assert(i);

        /* This shows pretty information about a unit. See
         * print_property() for a low-level property printer */

        printf("%s", strna(i->id));

        if (i->description && !streq_ptr(i->id, i->description))
                printf(" - %s", i->description);

        printf("\n");

        if (i->following)
                printf("   Follow: unit currently follows state of %s\n", i->following);

        if (streq_ptr(i->load_state, "error")) {
                on = ansi_highlight_red();
                off = ansi_highlight_off();
        } else
                on = off = "";

        path = i->source_path ? i->source_path : i->fragment_path;

        if (i->load_error)
                printf("   Loaded: %s%s%s (Reason: %s)\n", on, strna(i->load_state), off, i->load_error);
        else if (path && i->unit_file_state)
                printf("   Loaded: %s%s%s (%s; %s)\n", on, strna(i->load_state), off, path, i->unit_file_state);
        else if (path)
                printf("   Loaded: %s%s%s (%s)\n", on, strna(i->load_state), off, path);
        else
                printf("   Loaded: %s%s%s\n", on, strna(i->load_state), off);

        if (!strv_isempty(i->dropin_paths)) {
                char **dropin;
                char *dir = NULL;
                bool last = false;

                STRV_FOREACH (dropin, i->dropin_paths) {
                        if (!dir || last) {
                                printf(dir ? "        " : "  Drop-In: ");

                                free(dir);

                                if (path_get_parent(*dropin, &dir) < 0) {
                                        log_oom();
                                        return;
                                }

                                printf("%s\n           %s", dir, draw_special_char(DRAW_TREE_RIGHT));
                        }

                        last = !(*(dropin + 1) && startswith(*(dropin + 1), dir));

                        printf("%s%s", path_get_file_name(*dropin), last ? "\n" : ", ");
                }

                free(dir);
        }

        ss = streq_ptr(i->active_state, i->sub_state) ? NULL : i->sub_state;

        if (streq_ptr(i->active_state, "failed")) {
                on = ansi_highlight_red();
                off = ansi_highlight_off();
        } else if (streq_ptr(i->active_state, "active") || streq_ptr(i->active_state, "reloading")) {
                on = ansi_highlight_green();
                off = ansi_highlight_off();
        } else
                on = off = "";

        if (ss)
                printf("   Active: %s%s (%s)%s", on, strna(i->active_state), ss, off);
        else
                printf("   Active: %s%s%s", on, strna(i->active_state), off);

        if (!isempty(i->result) && !streq(i->result, "success"))
                printf(" (Result: %s)", i->result);

        timestamp = (streq_ptr(i->active_state, "active") || streq_ptr(i->active_state, "reloading")) ?
                i->active_enter_timestamp :
                (streq_ptr(i->active_state, "inactive") || streq_ptr(i->active_state, "failed")) ?
                                                           i->inactive_enter_timestamp :
                streq_ptr(i->active_state, "activating") ? i->inactive_exit_timestamp :
                                                           i->active_exit_timestamp;

        s1 = format_timestamp_relative(since1, sizeof(since1), timestamp);
        s2 = format_timestamp(since2, sizeof(since2), timestamp);

        if (s1)
                printf(" since %s; %s\n", s2, s1);
        else if (s2)
                printf(" since %s\n", s2);
        else
                printf("\n");

        if (!i->condition_result && i->condition_timestamp > 0) {
                s1 = format_timestamp_relative(since1, sizeof(since1), i->condition_timestamp);
                s2 = format_timestamp(since2, sizeof(since2), i->condition_timestamp);

                printf("           start condition failed at %s%s%s\n", s2, s1 ? "; " : "", s1 ? s1 : "");
                if (i->failed_condition_trigger)
                        printf("           none of the trigger conditions were met\n");
                else if (i->failed_condition)
                        printf("           %s=%s%s was not met\n",
                               i->failed_condition,
                               i->failed_condition_negate ? "!" : "",
                               i->failed_condition_param);
        }

        if (i->sysfs_path)
                printf("   Device: %s\n", i->sysfs_path);
        if (i->where)
                printf("    Where: %s\n", i->where);
        if (i->what)
                printf("     What: %s\n", i->what);

        STRV_FOREACH (t, i->documentation)
                printf(" %*s %s\n", 9, t == i->documentation ? "Docs:" : "", *t);

        STRV_FOREACH_PAIR (t, t2, i->listen)
                printf(" %*s %s (%s)\n", 9, t == i->listen ? "Listen:" : "", *t2, *t);

        if (i->accept)
                printf(" Accepted: %u; Connected: %u\n", i->n_accepted, i->n_connections);

        IWLIST_FOREACH (exec, p, i->exec) {
                _cleanup_free_ char *argv = NULL;
                bool good;

                /* Only show exited processes here */
                if (p->code == 0)
                        continue;

                argv = strv_join(p->argv, " ");
                printf("  Process: %u %s=%s ", p->pid, p->name, strna(argv));

                good = is_clean_exit_lsb(p->code, p->status, NULL);
                if (!good) {
                        on = ansi_highlight_red();
                        off = ansi_highlight_off();
                } else
                        on = off = "";

                printf("%s(code=%s, ", on, sigchld_code_to_string(p->code));

                if (p->code == CLD_EXITED) {
                        const char *c;

                        printf("status=%i", p->status);

                        c = exit_status_to_string(p->status, EXIT_STATUS_SYSTEMD);
                        if (c)
                                printf("/%s", c);

                } else
                        printf("signal=%s", signal_to_string(p->status));

                printf(")%s\n", off);

                if (i->main_pid == p->pid && i->start_timestamp == p->start_timestamp &&
                    i->exit_timestamp == p->start_timestamp)
                        /* Let's not show this twice */
                        i->main_pid = 0;

                if (p->pid == i->control_pid)
                        i->control_pid = 0;
        }

        if (i->main_pid > 0 || i->control_pid > 0) {
                if (i->main_pid > 0) {
                        printf(" Main PID: %u", (unsigned) i->main_pid);

                        if (i->running) {
                                _cleanup_free_ char *comm = NULL;
                                get_process_comm(i->main_pid, &comm);
                                if (comm)
                                        printf(" (%s)", comm);
                        } else if (i->exit_code > 0) {
                                printf(" (code=%s, ", sigchld_code_to_string(i->exit_code));

                                if (i->exit_code == CLD_EXITED) {
                                        const char *c;

                                        printf("status=%i", i->exit_status);

                                        c = exit_status_to_string(i->exit_status, EXIT_STATUS_SYSTEMD);
                                        if (c)
                                                printf("/%s", c);

                                } else
                                        printf("signal=%s", signal_to_string(i->exit_status));
                                printf(")");
                        }

                        if (i->control_pid > 0)
                                printf(";");
                }

                if (i->control_pid > 0) {
                        _cleanup_free_ char *c = NULL;

                        printf(" %8s: %u", i->main_pid ? "" : " Control", (unsigned) i->control_pid);

                        get_process_comm(i->control_pid, &c);
                        if (c)
                                printf(" (%s)", c);
                }

                printf("\n");
        }

        if (i->status_text)
                printf("   Status: \"%s\"\n", i->status_text);

#ifdef Use_PTGroups
        if (i->ptgroup) {
                unsigned c;

                printf("   PTGroup: %s\n", cJSON_GetObjectItem(i->ptgroup, "full_name")->valuestring);

                if (arg_transport != TRANSPORT_SSH) {
                        unsigned k = 0;
                        pid_t extra[2];
                        char prefix[] = "           ";

                        c = columns();
                        if (c > sizeof(prefix) - 1)
                                c -= sizeof(prefix) - 1;
                        else
                                c = 0;

                        if (i->main_pid > 0)
                                extra[k++] = i->main_pid;

                        if (i->control_pid > 0)
                                extra[k++] = i->control_pid;

                        show_ptgroup_and_extra(i->ptgroup, prefix, c, false, extra, k, flags);
                }
        }
#endif

#ifdef Use_CGroups
        if (i->control_group &&
            (i->main_pid > 0 || i->control_pid > 0
             || cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, i->control_group, false) == 0
             )) {
                unsigned c;

                printf("   CGroup: %s\n", i->control_group);

                if (arg_transport != TRANSPORT_SSH) {
                        unsigned k = 0;
                        pid_t extra[2];
                        char prefix[] = "           ";

                        c = columns();
                        if (c > sizeof(prefix) - 1)
                                c -= sizeof(prefix) - 1;
                        else
                                c = 0;

                        if (i->main_pid > 0)
                                extra[k++] = i->main_pid;

                        if (i->control_pid > 0)
                                extra[k++] = i->control_pid;

                        show_cgroup_and_extra(
                                SYSTEMD_CGROUP_CONTROLLER, i->control_group, prefix, c, false, extra, k, flags);
                }
        }
#endif

        if (i->id && arg_transport != TRANSPORT_SSH) {
                printf("\n");
#ifdef Have_Journal
                show_journal_by_unit(
                        stdout,
                        i->id,
                        arg_output,
                        0,
                        i->inactive_exit_timestamp_monotonic,
                        arg_lines,
                        getuid(),
                        flags,
                        arg_scope == UNIT_FILE_SYSTEM,
                        ellipsized);
#endif
        }

        if (i->need_daemon_reload)
                printf("\n%sWarning:%s Unit file changed on disk, 'systemctl %sdaemon-reload' recommended.\n",
                       ansi_highlight_red(),
                       ansi_highlight_off(),
                       arg_scope == UNIT_FILE_SYSTEM ? "" : "--user ");
}

static void show_unit_help(UnitStatusInfo *i) {
        char **p;

        assert(i);

        if (!i->documentation) {
                log_info("Documentation for %s not known.", i->id);
                return;
        }

        STRV_FOREACH (p, i->documentation) {

                if (startswith(*p, "man:")) {
                        size_t k;
                        char *e = NULL;
                        _cleanup_free_ char *page = NULL, *section = NULL;
                        const char *args[4] = { "man", NULL, NULL, NULL };
                        pid_t pid;

                        k = strlen(*p);

                        if ((*p)[k - 1] == ')')
                                e = strrchr(*p, '(');

                        if (e) {
                                page = strndup((*p) + 4, e - *p - 4);
                                section = strndup(e + 1, *p + k - e - 2);
                                if (!page || !section) {
                                        log_oom();
                                        return;
                                }

                                args[1] = section;
                                args[2] = page;
                        } else
                                args[1] = *p + 4;

                        pid = fork();
                        if (pid < 0) {
                                log_error("Failed to fork: %m");
                                continue;
                        }

                        if (pid == 0) {
                                /* Child */
                                execvp(args[0], (char **) args);
                                log_error("Failed to execute man: %m");
                                _exit(EXIT_FAILURE);
                        }

                        wait_for_terminate(pid, NULL);
                } else
                        log_info("Can't show: %s", *p);
        }
}

static int status_property(const char *name, DBusMessageIter *iter, UnitStatusInfo *i) {

        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Id"))
                                i->id = s;
                        else if (streq(name, "LoadState"))
                                i->load_state = s;
                        else if (streq(name, "ActiveState"))
                                i->active_state = s;
                        else if (streq(name, "SubState"))
                                i->sub_state = s;
                        else if (streq(name, "Description"))
                                i->description = s;
                        else if (streq(name, "FragmentPath"))
                                i->fragment_path = s;
                        else if (streq(name, "SourcePath"))
                                i->source_path = s;
#ifndef NOLEGACY
                        else if (streq(name, "DefaultControlGroup")) {
                                const char *e;
                                e = startswith(s, SYSTEMD_CGROUP_CONTROLLER ":");
                                if (e)
                                        i->control_group = e;
                        }
#endif
                        else if (streq(name, "ControlGroup"))
                                i->control_group = s;
#ifdef Use_PTGroups
                        else if (streq(name, "PTGroup")) {
                                i->ptgroup = cJSON_Parse(s);
                                if (!i->ptgroup)
                                        return -EINVAL;
                        }
#endif
                        else if (streq(name, "StatusText"))
                                i->status_text = s;
                        else if (streq(name, "PIDFile"))
                                i->pid_file = s;
                        else if (streq(name, "SysFSPath"))
                                i->sysfs_path = s;
                        else if (streq(name, "Where"))
                                i->where = s;
                        else if (streq(name, "What"))
                                i->what = s;
                        else if (streq(name, "Following"))
                                i->following = s;
                        else if (streq(name, "UnitFileState"))
                                i->unit_file_state = s;
                        else if (streq(name, "Result"))
                                i->result = s;
                }

                break;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;

                dbus_message_iter_get_basic(iter, &b);

                if (streq(name, "Accept"))
                        i->accept = b;
                else if (streq(name, "NeedDaemonReload"))
                        i->need_daemon_reload = b;
                else if (streq(name, "ConditionResult"))
                        i->condition_result = b;

                break;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "MainPID")) {
                        if (u > 0) {
                                i->main_pid = (pid_t) u;
                                i->running = true;
                        }
                } else if (streq(name, "ControlPID"))
                        i->control_pid = (pid_t) u;
                else if (streq(name, "ExecMainPID")) {
                        if (u > 0)
                                i->main_pid = (pid_t) u;
                } else if (streq(name, "NAccepted"))
                        i->n_accepted = u;
                else if (streq(name, "NConnections"))
                        i->n_connections = u;

                break;
        }

        case DBUS_TYPE_INT32: {
                int32_t j;

                dbus_message_iter_get_basic(iter, &j);

                if (streq(name, "ExecMainCode"))
                        i->exit_code = (int) j;
                else if (streq(name, "ExecMainStatus"))
                        i->exit_status = (int) j;

                break;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "ExecMainStartTimestamp"))
                        i->start_timestamp = (usec_t) u;
                else if (streq(name, "ExecMainExitTimestamp"))
                        i->exit_timestamp = (usec_t) u;
                else if (streq(name, "ActiveEnterTimestamp"))
                        i->active_enter_timestamp = (usec_t) u;
                else if (streq(name, "InactiveEnterTimestamp"))
                        i->inactive_enter_timestamp = (usec_t) u;
                else if (streq(name, "InactiveExitTimestamp"))
                        i->inactive_exit_timestamp = (usec_t) u;
                else if (streq(name, "InactiveExitTimestampMonotonic"))
                        i->inactive_exit_timestamp_monotonic = (usec_t) u;
                else if (streq(name, "ActiveExitTimestamp"))
                        i->active_exit_timestamp = (usec_t) u;
                else if (streq(name, "ConditionTimestamp"))
                        i->condition_timestamp = (usec_t) u;

                break;
        }

        case DBUS_TYPE_ARRAY: {

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && startswith(name, "Exec")) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                ExecStatusInfo *info;
                                int r;

                                info = new0(ExecStatusInfo, 1);
                                if (!info)
                                        return -ENOMEM;

                                info->name = strdup(name);
                                if (!info->name) {
                                        free(info);
                                        return -ENOMEM;
                                }

                                r = exec_status_info_deserialize(&sub, info);
                                if (r < 0) {
                                        free(info);
                                        return r;
                                }

                                IWLIST_PREPEND(ExecStatusInfo, exec, i->exec, info);

                                dbus_message_iter_next(&sub);
                        }

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Listen")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *type, *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0) {
                                        int r;

                                        r = strv_extend(&i->listen, type);
                                        if (r < 0)
                                                return r;
                                        r = strv_extend(&i->listen, path);
                                        if (r < 0)
                                                return r;
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING && streq(name, "DropInPaths")) {
                        int r = bus_parse_strv_iter(iter, &i->dropin_paths);
                        if (r < 0)
                                return r;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING && streq(name, "Documentation")) {

                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING) {
                                const char *s;
                                int r;

                                dbus_message_iter_get_basic(&sub, &s);

                                r = strv_extend(&i->documentation, s);
                                if (r < 0)
                                        return r;

                                dbus_message_iter_next(&sub);
                        }

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Conditions")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *cond, *param;
                                dbus_bool_t trigger, negate;
                                dbus_int32_t state;

                                dbus_message_iter_recurse(&sub, &sub2);
                                log_debug("here");

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &cond, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &trigger, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &negate, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &param, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_INT32, &state, false) >= 0) {
                                        log_debug("%s %d %d %s %d", cond, trigger, negate, param, state);
                                        if (state < 0 && (!trigger || !i->failed_condition)) {
                                                i->failed_condition = cond;
                                                i->failed_condition_trigger = trigger;
                                                i->failed_condition_negate = negate;
                                                i->failed_condition_param = param;
                                        }
                                }

                                dbus_message_iter_next(&sub);
                        }
                }

                break;
        }

        case DBUS_TYPE_STRUCT: {

                if (streq(name, "LoadError")) {
                        DBusMessageIter sub;
                        const char *n, *message;
                        int r;

                        dbus_message_iter_recurse(iter, &sub);

                        r = bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &n, true);
                        if (r < 0)
                                return r;

                        r = bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &message, false);
                        if (r < 0)
                                return r;

                        if (!isempty(message))
                                i->load_error = message;
                }

                break;
        }
        }

        return 0;
}

static int print_property(const char *name, DBusMessageIter *iter) {
        assert(name);
        assert(iter);

        /* This is a low-level property printer, see
         * print_status_info() for the nicer output */

        if (arg_properties && !strv_find(arg_properties, name))
                return 0;

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;
                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32 && streq(name, "Job")) {
                        uint32_t u;

                        dbus_message_iter_get_basic(&sub, &u);

                        if (u)
                                printf("%s=%u\n", name, (unsigned) u);
                        else if (arg_all)
                                printf("%s=\n", name);

                        return 0;
                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "Unit")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (arg_all || s[0])
                                printf("%s=%s\n", name, s);

                        return 0;
                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "LoadError")) {
                        const char *a = NULL, *b = NULL;

                        if (bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &a, true) >= 0)
                                bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &b, false);

                        if (arg_all || !isempty(a) || !isempty(b))
                                printf("%s=%s \"%s\"\n", name, strempty(a), strempty(b));

                        return 0;
                }

                break;
        }

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT &&
                    streq(name, "EnvironmentFiles")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *path;
                                dbus_bool_t ignore;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &ignore, false) >= 0)
                                        printf("EnvironmentFile=%s (ignore_errors=%s)\n", path, yes_no(ignore));

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Paths")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);

                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *type, *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0)
                                        printf("%s=%s\n", type, path);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Listen")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *type, *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0)
                                        printf("Listen%s=%s\n", type, path);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Timers")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *base;
                                uint64_t value, next_elapse;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &base, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &value, true) >= 0 &&
                                    bus_iter_get_basic_and_next(
                                            &sub2, DBUS_TYPE_UINT64, &next_elapse, false) >= 0) {
                                        char timespan1[FORMAT_TIMESPAN_MAX], timespan2[FORMAT_TIMESPAN_MAX];

                                        printf("%s={ value=%s ; next_elapse=%s }\n",
                                               base,
                                               format_timespan(timespan1, sizeof(timespan1), value, 0),
                                               format_timespan(timespan2, sizeof(timespan2), next_elapse, 0));
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && startswith(name, "Exec")) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                ExecStatusInfo info = {};

                                if (exec_status_info_deserialize(&sub, &info) >= 0) {
                                        char timestamp1[FORMAT_TIMESTAMP_MAX],
                                                timestamp2[FORMAT_TIMESTAMP_MAX];
                                        _cleanup_free_ char *t;

                                        t = strv_join(info.argv, " ");

                                        printf("%s={ path=%s ; argv[]=%s ; ignore_errors=%s ; start_time=[%s] ; stop_time=[%s] ; pid=%u ; code=%s ; status=%i%s%s }\n",
                                               name,
                                               strna(info.path),
                                               strna(t),
                                               yes_no(info.ignore),
                                               strna(format_timestamp(
                                                       timestamp1, sizeof(timestamp1), info.start_timestamp)),
                                               strna(format_timestamp(
                                                       timestamp2, sizeof(timestamp2), info.exit_timestamp)),
                                               (unsigned) info.pid,
                                               sigchld_code_to_string(info.code),
                                               info.status,
                                               info.code == CLD_EXITED ? "" : "/",
                                               strempty(
                                                       info.code == CLD_EXITED ?
                                                               NULL :
                                                               signal_to_string(info.status)));
                                }

                                free(info.path);
                                strv_free(info.argv);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "DeviceAllow")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *path, *rwm;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &rwm, false) >= 0)
                                        printf("%s=%s %s\n", name, strna(path), strna(rwm));

                                dbus_message_iter_next(&sub);
                        }
                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "BlockIODeviceWeight")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *path;
                                uint64_t weight;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &weight, false) >= 0)
                                        printf("%s=%s %" PRIu64 "\n", name, strna(path), weight);

                                dbus_message_iter_next(&sub);
                        }
                        return 0;

                } else if (
                        dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT &&
                        (streq(name, "BlockIOReadBandwidth") || streq(name, "BlockIOWriteBandwidth"))) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *path;
                                uint64_t bandwidth;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &bandwidth, false) >=
                                            0)
                                        printf("%s=%s %" PRIu64 "\n", name, strna(path), bandwidth);

                                dbus_message_iter_next(&sub);
                        }
                        return 0;
                }


                break;
        }

        if (generic_print_property(name, iter, arg_all) > 0)
                return 0;

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(
        const char *verb,
        DBusConnection *bus,
        const char *path,
        bool show_properties,
        bool *new_line,
        bool *ellipsized) {
        _cleanup_free_ DBusMessage *reply = NULL;
        const char *interface = "";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;
        UnitStatusInfo info = {};
        ExecStatusInfo *p;

        assert(path);
        assert(new_line);

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (*new_line)
                printf("\n");

        *new_line = true;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_DICT_ENTRY);
                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                if (show_properties)
                        r = print_property(name, &sub3);
                else
                        r = status_property(name, &sub3, &info);
                if (r < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_next(&sub);
        }

        r = 0;

        if (!show_properties) {
                if (streq(verb, "help"))
                        show_unit_help(&info);
                else
                        print_status_info(&info, ellipsized);
        }

        strv_free(info.documentation);
        strv_free(info.dropin_paths);
        strv_free(info.listen);

        if (!streq_ptr(info.active_state, "active") && !streq_ptr(info.active_state, "reloading") &&
            streq(verb, "status")) {
                /* According to LSB: "program not running" */
                /* 0: program is running or service is OK
                 * 1: program is dead and /var/run pid file exists
                 * 2: program is dead and /var/lock lock file exists
                 * 3: program is not running
                 * 4: program or service status is unknown
                 */
                if (info.pid_file && access(info.pid_file, F_OK) == 0)
                        r = 1;
                else
                        r = 3;
        }

        while ((p = info.exec)) {
                IWLIST_REMOVE(ExecStatusInfo, exec, info.exec, p);
                exec_status_info_free(p);
        }

        return r;
}

static int show_one_by_pid(const char *verb, DBusConnection *bus, uint32_t pid, bool *new_line, bool *ellipsized) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *path = NULL;
        _cleanup_dbus_error_free_ DBusError error;
        int r;

        dbus_error_init(&error);

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnitByPID",
                &reply,
                NULL,
                DBUS_TYPE_UINT32,
                &pid,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                return -EIO;
        }

        r = show_one(verb, bus, path, false, new_line, ellipsized);
        return r;
}

static int show_all(
        const char *verb, DBusConnection *bus, bool show_properties, bool *new_line, bool *ellipsized) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ struct unit_info *unit_infos = NULL;
        unsigned c = 0;
        const struct unit_info *u;
        int r;

        r = get_unit_list(bus, &reply, &unit_infos, &c);
        if (r < 0)
                return r;

        qsort_safe(unit_infos, c, sizeof(struct unit_info), compare_unit_info);

        for (u = unit_infos; u < unit_infos + c; u++) {
                _cleanup_free_ char *p = NULL;

                if (!output_show_unit(u))
                        continue;

                p = unit_dbus_path_from_name(u->id);
                if (!p)
                        return log_oom();

                printf("%s -> '%s'\n", u->id, p);

                r = show_one(verb, bus, p, show_properties, new_line, ellipsized);

                if (r < 0)
                        return r;
        }

        return 0;
}

int show(DBusConnection *bus, char **args) {
        int r, ret = 0;
        bool show_properties, show_status, new_line = false;
        char **name;
        bool ellipsized = false;

        assert(bus);
        assert(args);

        show_properties = streq(args[0], "show");
        show_status = streq(args[0], "status");

        if (show_properties)
                pager_open_if_enabled();

        /* If no argument is specified inspect the manager itself */

        if (show_properties && strv_length(args) <= 1)
                return show_one(
                        args[0], bus, "/org/freedesktop/systemd1", show_properties, &new_line, &ellipsized);

        if (show_status && strv_length(args) <= 1) {
                pager_open_if_enabled();
                ret = show_all(args[0], bus, false, &new_line, &ellipsized);
        } else
                STRV_FOREACH (name, args + 1) {
                        uint32_t id;

                        if (safe_atou32(*name, &id) < 0) {
                                _cleanup_free_ char *p = NULL, *n = NULL;
                                /* Interpret as unit name */

                                n = unit_name_mangle(*name);
                                if (!n)
                                        return log_oom();

                                p = unit_dbus_path_from_name(n);
                                if (!p)
                                        return log_oom();

                                r = show_one(args[0], bus, p, show_properties, &new_line, &ellipsized);
                                if (r != 0)
                                        ret = r;

                        } else if (show_properties) {
                                _cleanup_free_ char *p = NULL;

                                /* Interpret as job id */
                                if (asprintf(&p, "/org/freedesktop/systemd1/job/%u", id) < 0)
                                        return log_oom();

                                r = show_one(args[0], bus, p, show_properties, &new_line, &ellipsized);
                                if (r != 0)
                                        ret = r;

                        } else {
                                /* Interpret as PID */
                                r = show_one_by_pid(args[0], bus, id, &new_line, &ellipsized);
                                if (r != 0)
                                        ret = r;
                        }
                }

        if (ellipsized && !arg_quiet)
                printf("Hint: Some lines were ellipsized, use -l to show in full.\n");

        return ret;
}

static int append_assignment(DBusMessageIter *iter, const char *assignment) {
        const char *eq;
        char *field;
        DBusMessageIter sub;
        int r;

        assert(iter);
        assert(assignment);

        eq = strchr(assignment, '=');
        if (!eq) {
                log_error("Not an assignment: %s", assignment);
                return -EINVAL;
        }

        field = strndupa(assignment, eq - assignment);
        eq++;

        if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &field))
                return log_oom();

        if (streq(field, "CPUAccounting") || streq(field, "MemoryAccounting") ||
            streq(field, "BlockIOAccounting")) {
                dbus_bool_t b;

                r = parse_boolean(eq);
                if (r < 0) {
                        log_error("Failed to parse boolean assignment %s.", assignment);
                        return -EINVAL;
                }

                b = r;
                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "b", &sub) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_BOOLEAN, &b))
                        return log_oom();

        } else if (streq(field, "MemoryLimit")) {
                off_t bytes;
                uint64_t u;

                r = parse_bytes(eq, &bytes);
                if (r < 0) {
                        log_error("Failed to parse bytes specification %s", assignment);
                        return -EINVAL;
                }

                u = bytes;
                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "t", &sub) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT64, &u))
                        return log_oom();

        } else if (streq(field, "CPUShares") || streq(field, "BlockIOWeight")) {
                uint64_t u;

                r = safe_atou64(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "t", &sub) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT64, &u))
                        return log_oom();

        } else if (streq(field, "DevicePolicy")) {

                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "s", &sub) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &eq))
                        return log_oom();

        } else if (streq(field, "DeviceAllow")) {
                DBusMessageIter sub2;

                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a(ss)", &sub) ||
                    !dbus_message_iter_open_container(&sub, DBUS_TYPE_ARRAY, "(ss)", &sub2))
                        return log_oom();

                if (!isempty(eq)) {
                        const char *path, *rwm;
                        DBusMessageIter sub3;
                        char *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                rwm = e + 1;
                        } else {
                                path = eq;
                                rwm = "";
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        if (!dbus_message_iter_open_container(&sub2, DBUS_TYPE_STRUCT, NULL, &sub3) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &path) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &rwm) ||
                            !dbus_message_iter_close_container(&sub2, &sub3))
                                return log_oom();
                }

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();

        } else if (streq(field, "BlockIOReadBandwidth") || streq(field, "BlockIOWriteBandwidth")) {
                DBusMessageIter sub2;

                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a(st)", &sub) ||
                    !dbus_message_iter_open_container(&sub, DBUS_TYPE_ARRAY, "(st)", &sub2))
                        return log_oom();

                if (!isempty(eq)) {
                        const char *path, *bandwidth;
                        DBusMessageIter sub3;
                        uint64_t u;
                        off_t bytes;
                        char *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                bandwidth = e + 1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = parse_bytes(bandwidth, &bytes);
                        if (r < 0) {
                                log_error("Failed to parse byte value %s.", bandwidth);
                                return -EINVAL;
                        }

                        u = (uint64_t) bytes;

                        if (!dbus_message_iter_open_container(&sub2, DBUS_TYPE_STRUCT, NULL, &sub3) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &path) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_UINT64, &u) ||
                            !dbus_message_iter_close_container(&sub2, &sub3))
                                return log_oom();
                }

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();

        } else if (streq(field, "BlockIODeviceWeight")) {
                DBusMessageIter sub2;

                if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a(st)", &sub) ||
                    !dbus_message_iter_open_container(&sub, DBUS_TYPE_ARRAY, "(st)", &sub2))
                        return log_oom();

                if (!isempty(eq)) {
                        const char *path, *weight;
                        DBusMessageIter sub3;
                        uint64_t u;
                        char *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                weight = e + 1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = safe_atou64(weight, &u);
                        if (r < 0) {
                                log_error("Failed to parse %s value %s.", field, weight);
                                return -EINVAL;
                        }
                        if (!dbus_message_iter_open_container(&sub2, DBUS_TYPE_STRUCT, NULL, &sub3) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &path) ||
                            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_UINT64, &u) ||
                            !dbus_message_iter_close_container(&sub2, &sub3))
                                return log_oom();
                }

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();

        } else {
                log_error("Unknown assignment %s.", assignment);
                return -EINVAL;
        }

        if (!dbus_message_iter_close_container(iter, &sub))
                return log_oom();

        return 0;
}

int set_property(DBusConnection *bus, char **args) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        _cleanup_free_ char *n = NULL;
        DBusMessageIter iter, sub;
        dbus_bool_t runtime;
        DBusError error;
        char **i;
        int r;

        dbus_error_init(&error);

        m = dbus_message_new_method_call(
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "SetUnitProperties");
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, &iter);

        runtime = arg_runtime;

        n = unit_name_mangle(args[1]);
        if (!n)
                return log_oom();

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &n) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &runtime) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &sub))
                return log_oom();

        STRV_FOREACH (i, args + 2) {
                DBusMessageIter sub2;

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                        return log_oom();

                r = append_assignment(&sub2, *i);
                if (r < 0)
                        return r;

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        if (!dbus_message_iter_close_container(&iter, &sub))
                return log_oom();

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return -EIO;
        }

        return 0;
}

int snapshot(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusError error;
        int r;
        dbus_bool_t cleanup = FALSE;
        DBusMessageIter iter, sub;
        const char *path, *id, *interface = "org.freedesktop.systemd1.Unit", *property = "Id";
        _cleanup_free_ char *n = NULL;

        dbus_error_init(&error);

        if (strv_length(args) > 1)
                n = unit_name_mangle_with_suffix(args[1], ".snapshot");
        else
                n = strdup("");
        if (!n)
                return log_oom();

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "CreateSnapshot",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &n,
                DBUS_TYPE_BOOLEAN,
                &cleanup,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return -EIO;
        }

        dbus_message_unref(reply);
        reply = NULL;

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_get_basic(&sub, &id);

        if (!arg_quiet)
                puts(id);

        return 0;
}

int delete_snapshot(DBusConnection *bus, char **args) {
        char **name;

        assert(args);

        STRV_FOREACH (name, args + 1) {
                _cleanup_free_ char *n = NULL;
                int r;

                n = unit_name_mangle_with_suffix(*name, ".snapshot");
                if (!n)
                        return log_oom();

                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "RemoveSnapshot",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING,
                        &n,
                        DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;
        }

        return 0;
}

int daemon_reload(DBusConnection *bus, char **args) {
        int r;
        const char *method;
        DBusError error;

        if (arg_action == ACTION_RELOAD)
                method = "Reload";
        else if (arg_action == ACTION_REEXEC)
                method = "Reexecute";
        else {
                assert(arg_action == ACTION_SYSTEMCTL);

                method = streq(args[0], "clear-jobs") || streq(args[0], "cancel") ? "ClearJobs" :
                        streq(args[0], "daemon-reexec")                           ? "Reexecute" :
                        streq(args[0], "reset-failed")                            ? "ResetFailed" :
                        streq(args[0], "halt")                                    ? "Halt" :
                        streq(args[0], "poweroff")                                ? "PowerOff" :
                        streq(args[0], "reboot")                                  ? "Reboot" :
                        streq(args[0], "kexec")                                   ? "KExec" :
                        streq(args[0], "exit")                                    ? "Exit" :
                                                 /* "daemon-reload" */ "Reload";
        }

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                method,
                NULL,
                &error,
                DBUS_TYPE_INVALID);

        if (r == -ENOENT && arg_action != ACTION_SYSTEMCTL)
                /* There's always a fallback possible for
                 * legacy actions. */
                r = -EADDRNOTAVAIL;
        else if ((r == -ETIMEDOUT || r == -ECONNRESET) && streq(method, "Reexecute"))
                /* On reexecution, we expect a disconnect, not a
                 * reply */
                r = 0;
        else if (r < 0)
                log_error("Failed to issue method call: %s", bus_error_message(&error));

        dbus_error_free(&error);
        return r;
}

int reset_failed(DBusConnection *bus, char **args) {
        int r = 0;
        char **name;

        if (strv_length(args) <= 1)
                return daemon_reload(bus, args);

        STRV_FOREACH (name, args + 1) {
                _cleanup_free_ char *n;

                n = unit_name_mangle(*name);
                if (!n)
                        return log_oom();

                r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ResetFailedUnit",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING,
                        &n,
                        DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;
        }

        return 0;
}

int show_environment(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2;
        int r;
        const char *interface = "org.freedesktop.systemd1.Manager", *property = "Environment";

        pager_open_if_enabled();

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.DBus.Properties",
                "Get",
                &reply,
                NULL,
                DBUS_TYPE_STRING,
                &interface,
                DBUS_TYPE_STRING,
                &property,
                DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&sub, &sub2);

        while (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_INVALID) {
                const char *text;

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_get_basic(&sub2, &text);
                puts(text);

                dbus_message_iter_next(&sub2);
        }

        return 0;
}

int switch_root(DBusConnection *bus, char **args) {
        unsigned l;
        const char *root;
        _cleanup_free_ char *init = NULL;

        l = strv_length(args);
        if (l < 2 || l > 3) {
                log_error("Wrong number of arguments.");
                return -EINVAL;
        }

        root = args[1];

        if (l >= 3)
                init = strdup(args[2]);
        else {
                parse_env_file("/proc/cmdline", WHITESPACE, "init", &init, NULL);

                if (!init)
                        init = strdup("");
        }
        if (!init)
                return log_oom();

        log_debug("switching root - root: %s; init: %s", root, init);

        return bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "SwitchRoot",
                NULL,
                NULL,
                DBUS_TYPE_STRING,
                &root,
                DBUS_TYPE_STRING,
                &init,
                DBUS_TYPE_INVALID);
}

int set_environment(DBusConnection *bus, char **args) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        const char *method;
        DBusMessageIter iter;
        int r;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        method = streq(args[0], "set-environment") ? "SetEnvironment" : "UnsetEnvironment";

        m = dbus_message_new_method_call(
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                method);
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, &iter);

        r = bus_append_strv_iter(&iter, args + 1);
        if (r < 0)
                return log_oom();

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return -EIO;
        }

        return 0;
}

static int enable_sysv_units(const char *verb, char **args) {
        int r = 0;

#if defined(HAVE_SYSV_COMPAT) && defined(HAVE_CHKCONFIG)
        unsigned f = 1, t = 1;
        LookupPaths paths = {};

        if (arg_scope != UNIT_FILE_SYSTEM)
                return 0;

        if (!streq(verb, "enable") && !streq(verb, "disable") && !streq(verb, "is-enabled"))
                return 0;

        /* Processes all SysV units, and reshuffles the array so that
         * afterwards only the native units remain */

        r = lookup_paths_init(&paths, SYSTEMD_SYSTEM, false, arg_root, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = 0;
        for (f = 0; args[f]; f++) {
                const char *name;
                _cleanup_free_ char *p = NULL, *q = NULL;
                bool found_native = false, found_sysv;
                unsigned c = 1;
                const char *argv[6] = { "/sbin/chkconfig", NULL, NULL, NULL, NULL };
                char **k, *l;
                int j;
                pid_t pid;
                siginfo_t status;

                name = args[f];

                if (!endswith(name, ".service"))
                        continue;

                if (path_is_absolute(name))
                        continue;

                STRV_FOREACH (k, paths.unit_path) {
                        if (!isempty(arg_root))
                                asprintf(&p, "%s/%s/%s", arg_root, *k, name);
                        else
                                asprintf(&p, "%s/%s", *k, name);

                        if (!p) {
                                r = log_oom();
                                goto finish;
                        }

                        found_native = access(p, F_OK) >= 0;
                        free(p);
                        p = NULL;

                        if (found_native)
                                break;
                }

                if (found_native)
                        continue;

                if (!isempty(arg_root))
                        asprintf(&p, "%s/" SYSTEM_SYSVINIT_PATH "/%s", arg_root, name);
                else
                        asprintf(&p, SYSTEM_SYSVINIT_PATH "/%s", name);
                if (!p) {
                        r = log_oom();
                        goto finish;
                }

                p[strlen(p) - sizeof(".service") + 1] = 0;
                found_sysv = access(p, F_OK) >= 0;

                if (!found_sysv)
                        continue;

                /* Mark this entry, so that we don't try enabling it as native unit */
                args[f] = (char *) "";

                log_info("%s is not a native service, redirecting to /sbin/chkconfig.", name);

                if (!isempty(arg_root))
                        argv[c++] = q = strappend("--root=", arg_root);

                argv[c++] = path_get_file_name(p);
                argv[c++] = streq(verb, "enable") ? "on" : streq(verb, "disable") ? "off" : "--level=5";
                argv[c] = NULL;

                l = strv_join((char **) argv, " ");
                if (!l) {
                        r = log_oom();
                        goto finish;
                }

                log_info("Executing %s", l);
                free(l);

                pid = fork();
                if (pid < 0) {
                        log_error("Failed to fork: %m");
                        r = -errno;
                        goto finish;
                } else if (pid == 0) {
                        /* Child */

                        execv(argv[0], (char **) argv);
                        _exit(EXIT_FAILURE);
                }

                j = wait_for_terminate(pid, &status);
                if (j < 0) {
                        log_error("Failed to wait for child: %s", strerror(-r));
                        r = j;
                        goto finish;
                }

                if (status.si_code == CLD_EXITED) {
                        if (streq(verb, "is-enabled")) {
                                if (status.si_status == 0) {
                                        if (!arg_quiet)
                                                puts("enabled");
                                        r = 1;
                                } else {
                                        if (!arg_quiet)
                                                puts("disabled");
                                }

                        } else if (status.si_status != 0) {
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        r = -EPROTO;
                        goto finish;
                }
        }

finish:
        lookup_paths_free(&paths);

        /* Drop all SysV units */
        for (f = 0, t = 0; args[f]; f++) {

                if (isempty(args[f]))
                        continue;

                args[t++] = args[f];
        }

        args[t] = NULL;

#endif
        return r;
}

static int mangle_names(char **original_names, char ***mangled_names) {
        char **i, **l, **name;

        l = new (char *, strv_length(original_names) + 1);
        if (!l)
                return log_oom();

        i = l;
        STRV_FOREACH (name, original_names) {

                /* When enabling units qualified path names are OK,
                 * too, hence allow them explicitly. */

                if (is_path(*name))
                        *i = strdup(*name);
                else
                        *i = unit_name_mangle(*name);

                if (!*i) {
                        strv_free(l);
                        return log_oom();
                }

                i++;
        }

        *i = NULL;
        *mangled_names = l;

        return 0;
}

int enable_unit(DBusConnection *bus, char **args) {
        const char *verb = args[0];
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0, i;
        int carries_install_info = -1;
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        int r;
        _cleanup_dbus_error_free_ DBusError error;
        _cleanup_strv_free_ char **mangled_names = NULL;

        dbus_error_init(&error);

        if (!args[1])
                return 0;

        r = mangle_names(args + 1, &mangled_names);
        if (r < 0)
                return r;

        r = enable_sysv_units(verb, mangled_names);
        if (r < 0)
                return r;

        /* If the operation was fully executed by the SysV compat,
         * let's finish early */
        if (strv_isempty(mangled_names))
                return 0;

        if (!bus || avoid_bus()) {
                if (streq(verb, "enable")) {
                        r = unit_file_enable(
                                arg_scope, arg_runtime, arg_root, mangled_names, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "disable"))
                        r = unit_file_disable(
                                arg_scope, arg_runtime, arg_root, mangled_names, &changes, &n_changes);
                else if (streq(verb, "reenable")) {
                        r = unit_file_reenable(
                                arg_scope, arg_runtime, arg_root, mangled_names, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "link"))
                        r = unit_file_link(
                                arg_scope, arg_runtime, arg_root, mangled_names, arg_force, &changes, &n_changes);
                else if (streq(verb, "preset")) {
                        r = unit_file_preset(
                                arg_scope, arg_runtime, arg_root, mangled_names, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "mask"))
                        r = unit_file_mask(
                                arg_scope, arg_runtime, arg_root, mangled_names, arg_force, &changes, &n_changes);
                else if (streq(verb, "unmask"))
                        r = unit_file_unmask(
                                arg_scope, arg_runtime, arg_root, mangled_names, &changes, &n_changes);
                else if (streq(verb, "set-default"))
                        r = unit_file_set_default(arg_scope, arg_root, args[1], &changes, &n_changes);
                else
                        assert_not_reached("Unknown verb");

                if (r < 0) {
                        log_error("Operation failed: %s", strerror(-r));
                        goto finish;
                }

                if (!arg_quiet) {
                        for (i = 0; i < n_changes; i++) {
                                if (changes[i].type == UNIT_FILE_SYMLINK)
                                        log_info("ln -s '%s' '%s'", changes[i].source, changes[i].path);
                                else
                                        log_info("rm '%s'", changes[i].path);
                        }
                }

                r = 0;
        } else {
                const char *method;
                bool send_force = true, expect_carries_install_info = false;
                dbus_bool_t a, b;
                DBusMessageIter iter, sub, sub2;

                if (streq(verb, "enable")) {
                        method = "EnableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "disable")) {
                        method = "DisableUnitFiles";
                        send_force = false;
                } else if (streq(verb, "reenable")) {
                        method = "ReenableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "link"))
                        method = "LinkUnitFiles";
                else if (streq(verb, "preset")) {
                        method = "PresetUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "mask"))
                        method = "MaskUnitFiles";
                else if (streq(verb, "unmask")) {
                        method = "UnmaskUnitFiles";
                        send_force = false;
                } else if (streq(verb, "set-default")) {
                        method = "SetDefaultTarget";
                } else
                        assert_not_reached("Unknown verb");

                m = dbus_message_new_method_call(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        method);
                if (!m) {
                        r = log_oom();
                        goto finish;
                }

                dbus_message_iter_init_append(m, &iter);

                r = bus_append_strv_iter(&iter, mangled_names);
                if (r < 0) {
                        log_error("Failed to append unit files.");
                        goto finish;
                }

                a = arg_runtime;
                if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &a)) {
                        log_error("Failed to append runtime boolean.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (send_force) {
                        b = arg_force;

                        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &b)) {
                                log_error("Failed to append force boolean.");
                                r = -ENOMEM;
                                goto finish;
                        }
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                if (!reply) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_iter_init(reply, &iter)) {
                        log_error("Failed to initialize iterator.");
                        goto finish;
                }

                if (expect_carries_install_info) {
                        r = bus_iter_get_basic_and_next(&iter, DBUS_TYPE_BOOLEAN, &b, true);
                        if (r < 0) {
                                log_error("Failed to parse reply.");
                                goto finish;
                        }

                        carries_install_info = b;
                }

                if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&iter, &sub);
                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                        const char *type, *path, *source;

                        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &source, false) < 0) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        if (!arg_quiet) {
                                if (streq(type, "symlink"))
                                        log_info("ln -s '%s' '%s'", source, path);
                                else
                                        log_info("rm '%s'", path);
                        }

                        dbus_message_iter_next(&sub);
                }

                /* Try to reload if enabeld */
                if (!arg_no_reload)
                        r = daemon_reload(bus, args);
        }

        if (carries_install_info == 0)
                log_warning(
                        "The unit files have no [Install] section. They are not meant to be enabled\n"
                        "using systemctl.\n"
                        "Possible reasons for having this kind of units are:\n"
                        "1) A unit may be statically enabled by being symlinked from another unit's\n"
                        "   .wants/ or .requires/ directory.\n"
                        "2) A unit's purpose may be to act as a helper for some other unit which has\n"
                        "   a requirement dependency on it.\n"
                        "3) A unit may be started when needed via activation (socket, path, timer,\n"
                        "   D-Bus, udev, scripted systemctl call, ...).\n");

finish:
        unit_file_changes_free(changes, n_changes);

        return r;
}

int unit_is_enabled(DBusConnection *bus, char **args) {
        _cleanup_dbus_error_free_ DBusError error;
        int r;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        bool enabled;
        char **name;
        _cleanup_strv_free_ char **mangled_names = NULL;

        dbus_error_init(&error);

        r = mangle_names(args + 1, &mangled_names);
        if (r < 0)
                return r;

        r = enable_sysv_units(args[0], mangled_names);
        if (r < 0)
                return r;

        enabled = r > 0;

        if (!bus || avoid_bus()) {

                STRV_FOREACH (name, mangled_names) {
                        UnitFileState state;

                        state = unit_file_get_state(arg_scope, arg_root, *name);

                        if (state < 0)
                                return state;

                        if (state == UNIT_FILE_ENABLED || state == UNIT_FILE_ENABLED_RUNTIME ||
                            state == UNIT_FILE_STATIC)
                                enabled = true;

                        if (!arg_quiet)
                                puts(unit_file_state_to_string(state));
                }

        } else {
                STRV_FOREACH (name, mangled_names) {
                        const char *s;

                        r = bus_method_call_with_reply(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "GetUnitFileState",
                                &reply,
                                NULL,
                                DBUS_TYPE_STRING,
                                name,
                                DBUS_TYPE_INVALID);

                        if (r)
                                return r;

                        if (!dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID)) {
                                log_error("Failed to parse reply: %s", bus_error_message(&error));
                                return -EIO;
                        }

                        dbus_message_unref(reply);
                        reply = NULL;

                        if (streq(s, "enabled") || streq(s, "enabled-runtime") || streq(s, "static"))
                                enabled = true;

                        if (!arg_quiet)
                                puts(s);
                }
        }

        return enabled ? 0 : 1;
}