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

#include <errno.h>

#include "unit.h"
#include "device.h"
#include "strv.h"
#include "log.h"
#include "unit-name.h"
#include "dbus-device.h"
#include "def.h"
#include "path-util.h"
#include "libudev.h"

#ifdef Use_Libdevattr
#define MainUnitNamePrefix "dev-"
#define udev_device_get_syspath udev_device_get_devnode
#define udev_monitor_new_from_netlink(u, name) udev_monitor_new(u)
#elif !defined(Sys_Plat_Linux)
#define MainUnitNamePrefix "dev-"
#else
#define MainUnitNamePrefix "sys-"
#endif

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_PLUGGED] = UNIT_ACTIVE
};

static void device_unset_sysfs(Device *d) {
        Device *first;

        assert(d);

        if (!d->sysfs)
                return;

        /* Remove this unit from the chain of devices which share the
         * same sysfs path. */
        first = hashmap_get(UNIT(d)->manager->devices_by_sysfs, d->sysfs);
        IWLIST_REMOVE(Device, same_sysfs, first, d);

        if (first)
                hashmap_remove_and_replace(UNIT(d)->manager->devices_by_sysfs, d->sysfs, first->sysfs, first);
        else
                hashmap_remove(UNIT(d)->manager->devices_by_sysfs, d->sysfs);

        free(d->sysfs);
        d->sysfs = NULL;
}

static void device_init(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(UNIT(d)->load_state == UNIT_STUB);

        /* In contrast to all other unit types we timeout jobs waiting
         * for devices by default. This is because they otherwise wait
         * indefinitely for plugged in devices, something which cannot
         * happen for the other units since their operations time out
         * anyway. */
        UNIT(d)->job_timeout = u->manager->default_timeout_start_usec;

        UNIT(d)->ignore_on_isolate = true;
        UNIT(d)->ignore_on_snapshot = true;
}

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);

        device_unset_sysfs(d);
}

static void device_set_state(Device *d, DeviceState state) {
        DeviceState old_state;
        assert(d);

        old_state = d->state;
        d->state = state;

        if (state != old_state)
                log_debug_unit(UNIT(d)->id,
                               "%s changed %s -> %s", UNIT(d)->id,
                               device_state_to_string(old_state),
                               device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], true);
}

static int device_coldplug(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->state == DEVICE_DEAD);

        if (d->sysfs)
                device_set_state(d, DEVICE_PLUGGED);

        return 0;
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {
        Device *d = DEVICE(u);

        assert(d);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n",
                prefix, device_state_to_string(d->state),
                prefix, strna(d->sysfs));
}

_pure_ static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

_pure_ static const char *device_sub_state_to_string(Unit *u) {
        assert(u);

        return device_state_to_string(DEVICE(u)->state);
}

static int device_add_escaped_name(Unit *u, const char *dn) {
#ifdef Use_Libdevattr
        char *t;
#endif
        char *e;
        int r;

        assert(u);
        assert(dn);
#ifndef Use_Libdevattr
        assert(dn[0] == '/');
#endif

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

#ifdef Use_Libdevattr /* add dev- prefix */
         if (asprintf(&t, "dev-%s", e) < 0)
        {
                free (e);
                return -ENOMEM;
        }
        free(e);
        e = t;
#endif

        r = unit_add_name(u, e);
        free(e);

        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_find_escape_name(Manager *m, const char *dn, Unit **_u) {
#ifdef Use_Libdevattr
        char *t;
#endif
        char *e;
        Unit *u;

        assert(m);
        assert(dn);
#ifndef Use_Libdevattr
        assert(dn[0] == '/');
#endif
        assert(_u);

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

#ifdef Use_Libdevattr /* add dev- prefix */
         if (asprintf(&t, "dev-%s", e) < 0)
        {
                free (e);
                return -ENOMEM;
        }
        free(e);
        e = t;
#endif

        u = manager_get_unit(m, e);
        free(e);

        if (u) {
                *_u = u;
                return 1;
        }

        return 0;
}

static int device_update_unit(Manager *m, struct udev_device *dev, const char *path, bool main) {
        const char *sysfs, *model;
        Unit *u = NULL;
        int r;
        bool delete;

        assert(m);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        if ((r = device_find_escape_name(m, path, &u)) < 0)
                return r;

        if (u && DEVICE(u)->sysfs && !path_equal(DEVICE(u)->sysfs, sysfs))
                return -EEXIST;

        if (!u) {
                delete = true;

                u = unit_new(m, sizeof(Device));
                if (!u)
                        return -ENOMEM;

                r = device_add_escaped_name(u, path);
                if (r < 0)
                        goto fail;

                unit_add_to_load_queue(u);
        } else
                delete = false;

        /* If this was created via some dependency and has not
         * actually been seen yet ->sysfs will not be
         * initialized. Hence initialize it if necessary. */

        if (!DEVICE(u)->sysfs) {
                Device *first;

                if (!(DEVICE(u)->sysfs = strdup(sysfs))) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (!m->devices_by_sysfs)
                        if (!(m->devices_by_sysfs = hashmap_new(string_hash_func, string_compare_func))) {
                                r = -ENOMEM;
                                goto fail;
                        }

                first = hashmap_get(m->devices_by_sysfs, sysfs);
                IWLIST_PREPEND(Device, same_sysfs, first, DEVICE(u));

                if ((r = hashmap_replace(m->devices_by_sysfs, DEVICE(u)->sysfs, first)) < 0)
                        goto fail;
        }

        if ((model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE")) ||
            (model = udev_device_get_property_value(dev, "ID_MODEL"))) {
                if ((r = unit_set_description(u, model)) < 0)
                        goto fail;
        } else
                if ((r = unit_set_description(u, path)) < 0)
                        goto fail;

        if (main) {
                /* The additional systemd udev properties we only
                 * interpret for the main object */
                const char *wants, *alias;

                alias = udev_device_get_property_value(dev, "SYSTEMD_ALIAS");
                if (alias) {
                        char *state, *w;
                        size_t l;

                        FOREACH_WORD_QUOTED(w, l, alias, state) {
                                char *e;

                                e = strndup(w, l);
                                if (!e) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                if (!is_path(e)) {
                                        log_warning("SYSTEMD_ALIAS for %s is not a path, ignoring: %s", sysfs, e);
                                        free(e);
                                } else {
                                        device_update_unit(m, dev, e, false);
                                        free(e);
                                }
                        }
                }

                if (u->manager->running_as == SYSTEMD_SYSTEM &&
                    (wants = udev_device_get_property_value(dev, "SYSTEMD_WANTS"))) {

                        char *state, *w;
                        size_t l;

                        FOREACH_WORD_QUOTED(w, l, wants, state) {
                                char *e, *n;

                                e = strndup(w, l);
                                if (!e) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                                n = unit_name_mangle(e);
                                if (!n) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                                free(e);

                                r = unit_add_dependency_by_name(u, UNIT_WANTS, n, NULL, true);
                                free(n);
                                if (r < 0)
                                        goto fail;
                        }
                }
        }

        unit_add_to_dbus_queue(u);
        return 0;

fail:
        log_warning("Failed to load device unit: %s", strerror(-r));

        if (delete && u)
                unit_free(u);

        return r;
}

static int device_process_new_device(Manager *m, struct udev_device *dev, bool update_state) {
        const char *sysfs, *dn;
        struct udev_list_entry *item = NULL, *first = NULL;
        int r;

        assert(m);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        /* Add the main unit named after the sysfs path */
        r = device_update_unit(m, dev, sysfs, true);
        if (r < 0)
                return r;

#ifdef Sys_Plat_Linux /* no devlinks nor sysfs in DFBSD's UDev */
        /* Add an additional unit for the device node */
        if ((dn = udev_device_get_devnode(dev)))
                device_update_unit(m, dev, dn, false);

        /* Add additional units for all symlinks */
        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first) {
                const char *p;
                struct stat st;

                /* Don't bother with the /dev/block links */

                p = udev_list_entry_get_name(item);

                if (path_startswith(p, "/dev/block/") ||
                    path_startswith(p, "/dev/char/"))
                        continue;

                /* Verify that the symlink in the FS actually belongs
                 * to this device. This is useful to deal with
                 * conflicting devices, e.g. when two disks want the
                 * same /dev/disk/by-label/xxx link because they have
                 * the same label. We want to make sure that the same
                 * device that won the symlink wins in systemd, so we
                 * check the device node major/minor*/
                if (stat(p, &st) >= 0)
                        if ((!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode)) ||
                            st.st_rdev != udev_device_get_devnum(dev))
                                continue;

                device_update_unit(m, dev, p, false);
        }
#endif

        if (update_state) {
                Device *d, *l;

                manager_dispatch_load_queue(m);

                l = hashmap_get(m->devices_by_sysfs, sysfs);
                IWLIST_FOREACH(same_sysfs, d, l)
                device_set_state(d, DEVICE_PLUGGED);
        }

        return 0;
}

#ifdef Use_Libudev
static int device_process_path(Manager *m, const char *path, bool update_state) {
        int r;
        struct udev_device *dev;

        assert(m);
        assert(path);

        if (!(dev = udev_device_new_from_syspath(m->udev, path))) {
                log_warning("Failed to get udev device object from udev for path %s.", path);
                return -ENOMEM;
        }

        r = device_process_new_device(m, dev, update_state);
        udev_device_unref(dev);
        return r;
}
#endif

static int device_process_removed_device(Manager *m, struct udev_device *dev) {
        const char *sysfs;
        Device *d;

        assert(m);
        assert(dev);

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        /* Remove all units of this sysfs path */
        while ((d = hashmap_get(m->devices_by_sysfs, sysfs))) {
                device_unset_sysfs(d);
                device_set_state(d, DEVICE_DEAD);
        }

        return 0;
}

static Unit *device_following(Unit *u) {
        Device *d = DEVICE(u);
        Device *other, *first = NULL;

        assert(d);

        if (startswith(u->id, MainUnitNamePrefix))
                return NULL;

        /* Make everybody follow the unit that's named after the sysfs path */
        for (other = d->same_sysfs_next; other; other = other->same_sysfs_next)
                if (startswith(UNIT(other)->id, MainUnitNamePrefix))
                        return UNIT(other);

        for (other = d->same_sysfs_prev; other; other = other->same_sysfs_prev) {
                if (startswith(UNIT(other)->id, MainUnitNamePrefix))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int device_following_set(Unit *u, Set **_s) {
        Device *d = DEVICE(u);
        Device *other;
        Set *s;
        int r;

        assert(d);
        assert(_s);

        if (!d->same_sysfs_prev && !d->same_sysfs_next) {
                *_s = NULL;
                return 0;
        }

        if (!(s = set_new(NULL, NULL)))
                return -ENOMEM;

        for (other = d->same_sysfs_next; other; other = other->same_sysfs_next)
                if ((r = set_put(s, other)) < 0)
                        goto fail;

        for (other = d->same_sysfs_prev; other; other = other->same_sysfs_prev)
                if ((r = set_put(s, other)) < 0)
                        goto fail;

        *_s = s;
        return 1;

fail:
        set_free(s);
        return r;
}

static void device_shutdown(Manager *m) {
        assert(m);

        if (m->udev_monitor) {
                udev_monitor_unref(m->udev_monitor);
                m->udev_monitor = NULL;
        }

        if (m->udev) {
                udev_unref(m->udev);
                m->udev = NULL;
        }

        hashmap_free(m->devices_by_sysfs);
        m->devices_by_sysfs = NULL;
}

static void udev_io_cb(struct ev_loop *evloop, ev_io *watch, int revents)
{
        device_fd_event(watch->data, revents);
}

static int device_enumerate(Manager *m) {
        int r;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        if (!m->udev) {
                if (!(m->udev = udev_new()))
                {
                        log_error("udev_new() failed\n");
                        return -ENOMEM;
                }

                if (!(m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev"))) {
                        log_error("udev_monitor_new() failed\n");
                        r = -ENOMEM;
                        goto fail;
                }

#ifdef Sys_Plat_Linux
                /* This will fail if we are unprivileged, but that
                 * should not matter much, as user instances won't run
                 * during boot. */
                udev_monitor_set_receive_buffer_size(m->udev_monitor, 128*1024*1024);

                if (udev_monitor_filter_add_match_tag(m->udev_monitor, "systemd") < 0) {
                        r = -ENOMEM;
                        goto fail;
                }
#elif defined Use_Libdevattr
                if (udev_monitor_filter_add_nomatch_expr(m->udev_monitor, "name", "fd/*") < 0 ||
                    udev_monitor_filter_add_nomatch_expr(m->udev_monitor, "name", "pty*") < 0 ||
                    udev_monitor_filter_add_nomatch_expr(m->udev_monitor, "name", "tty*") < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

#endif

                if (udev_monitor_enable_receiving(m->udev_monitor) < 0) {
                        r = -EIO;
                        goto fail;
                }

                ev_io_init(&m->udev_watch, udev_io_cb, udev_monitor_get_fd(m->udev_monitor), EV_READ);
                m->udev_watch.data = m;
                ev_io_start(m->evloop, &m->udev_watch);
                /* if (failed to add watch)
                        return -errno; */
        }

        if (!(e = udev_enumerate_new(m->udev))) {
                r = -ENOMEM;
                goto fail;
        }
#ifdef Sys_Plat_Linux
        if (udev_enumerate_add_match_tag(e, "systemd") < 0) {
                r = -EIO;
                goto fail;
        }
#elif defined(Use_Libdevattr)
        /* Filter out fdescfs, and also pty* and tty* as every single possible
         * node seems to be enumerated.... */
        if (udev_enumerate_add_nomatch_expr(e, "name", "fd/*") < 0 ||
            udev_enumerate_add_nomatch_expr(e, "name", "pty*") < 0 ||
            udev_enumerate_add_nomatch_expr(e, "name", "tty*") < 0)
        {
                r = -EIO;
                goto fail;
        }
#endif

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto fail;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first)
#ifdef Use_Libudev
                device_process_path(m, udev_list_entry_get_name(item), false);
#else
                device_process_new_device(m, udev_list_entry_get_device(item), false);
#endif

        udev_enumerate_unref(e);
        return 0;

fail:
        if (e)
                udev_enumerate_unref(e);

        device_shutdown(m);
        return r;
}

void device_fd_event(Manager *m, int events) {
        struct udev_device *dev;
        int r;
        const char *action, *ready;

        assert(m);

        if (events != EV_READ) {
                static RATELIMIT_DEFINE(limit, 10*USEC_PER_SEC, 5);

                if (!ratelimit_test(&limit))
                        log_error("Failed to get udev event: %m");
                if (!(events & EV_READ))
                        return;
        }

        if (!(dev = udev_monitor_receive_device(m->udev_monitor))) {
                /*
                 * libudev might filter-out devices which pass the bloom filter,
                 * so getting NULL here is not necessarily an error
                 */
                return;
        }

        if (!(action = udev_device_get_action(dev))) {
                log_error("Failed to get udev action string.");
                goto fail;
        }

        ready = udev_device_get_property_value(dev, "SYSTEMD_READY");

        if (streq(action, "remove") || (ready && parse_boolean(ready) == 0)) {
                if ((r = device_process_removed_device(m, dev)) < 0) {
                        log_error("Failed to process udev device event: %s", strerror(-r));
                        goto fail;
                }
        } else {
                if ((r = device_process_new_device(m, dev, true)) < 0) {
                        log_error("Failed to process udev device event: %s", strerror(-r));
                        goto fail;
                }
        }

fail:
        udev_device_unref(dev);
}

static const char* const device_state_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = "dead",
        [DEVICE_PLUGGED] = "plugged"
};

DEFINE_STRING_TABLE_LOOKUP(device_state, DeviceState);

const UnitVTable device_vtable = {
        .object_size = sizeof(Device),
        .sections =
                "Unit\0"
                "Device\0"
                "Install\0",

        .no_instances = true,

        .init = device_init,

        .load = unit_load_fragment_and_dropin_optional,
        .done = device_done,
        .coldplug = device_coldplug,

        .dump = device_dump,

        .active_state = device_active_state,
        .sub_state_to_string = device_sub_state_to_string,

        .bus_interface = SCHEDULER_DBUS_INTERFACE ".Device",
        .bus_message_handler = bus_device_message_handler,
        .bus_invalidating_properties =  bus_device_invalidating_properties,

        .following = device_following,
        .following_set = device_following_set,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Expecting device %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Found device %s.",
                        [JOB_TIMEOUT]    = "Timed out waiting for device %s.",
                },
        },
};
