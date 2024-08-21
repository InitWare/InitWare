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

#include "alloc-util.h"
#include "bus-introspect.h"
#include "bus-internal.h"
#include "bus-objects.h"
#include "bus-protocol.h"
#include "bus-signature.h"
#include "sd-bus-protocol.h"
#include "util.h"

int introspect_begin(struct introspect *i, bool trusted) {
        FILE *f;

        assert(i);

        *i = (struct introspect) {
                .trusted = trusted,
        };

        f = memstream_init(&i->m);
        if (!f)
                return -ENOMEM;

        fputs(BUS_INTROSPECT_DOCTYPE
              "<node>\n", f);

        return 0;
}

int introspect_write_default_interfaces(struct introspect *i, bool object_manager) {
        assert(i);
        assert(i->m.f);

        fputs(BUS_INTROSPECT_INTERFACE_PEER
              BUS_INTROSPECT_INTERFACE_INTROSPECTABLE
              BUS_INTROSPECT_INTERFACE_PROPERTIES, i->m.f);

        if (object_manager)
                fputs(BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER, i->m.f);

        return 0;
}

static int set_interface_name(struct introspect *i, const char *interface_name) {
        assert(i);
        assert(i->m.f);

        if (streq_ptr(i->interface_name, interface_name))
                return 0;

        if (i->interface_name)
                fputs(" </interface>\n", i->m.f);

        if (interface_name)
                fprintf(i->m.f, " <interface name=\"%s\">\n", interface_name);

        return free_and_strdup(&i->interface_name, interface_name);
}

int introspect_write_child_nodes(struct introspect *i, OrderedSet *s, const char *prefix) {
        char *node;

        assert(i);
        assert(i->m.f);
        assert(prefix);

        assert_se(set_interface_name(i, NULL) >= 0);

        while ((node = ordered_set_steal_first(s))) {
                const char *e;

                e = object_path_startswith(node, prefix);
                if (e && e[0])
                        fprintf(i->m.f, " <node name=\"%s\"/>\n", e);

                free(node);
        }

        return 0;
}

static void introspect_write_flags(struct introspect *i, int type, uint64_t flags) {
        assert(i);
        assert(i->m.f);

        if (flags & SD_BUS_VTABLE_DEPRECATED)
                fputs("   <annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n", i->m.f);

        if (type == _SD_BUS_VTABLE_METHOD && (flags & SD_BUS_VTABLE_METHOD_NO_REPLY))
                fputs("   <annotation name=\"org.freedesktop.DBus.Method.NoReply\" value=\"true\"/>\n", i->m.f);

        if (IN_SET(type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY)) {
                if (flags & SD_BUS_VTABLE_PROPERTY_EXPLICIT)
                        fputs("   <annotation name=\"org.freedesktop.systemd1.Explicit\" value=\"true\"/>\n", i->m.f);

                if (flags & SD_BUS_VTABLE_PROPERTY_CONST)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"const\"/>\n", i->m.f);
                else if (flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"invalidates\"/>\n", i->m.f);
                else if (!(flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE))
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n", i->m.f);
        }

        if (!i->trusted &&
            IN_SET(type, _SD_BUS_VTABLE_METHOD, _SD_BUS_VTABLE_WRITABLE_PROPERTY) &&
            !(flags & SD_BUS_VTABLE_UNPRIVILEGED))
                fputs("   <annotation name=\"org.freedesktop.systemd1.Privileged\" value=\"true\"/>\n", i->m.f);
}

/* Note that "names" is both an input and an output parameter. It initially points to the first argument name in a
   NULL-separated list of strings, and is then advanced with each argument, and the resulting pointer is returned. */
static int introspect_write_arguments(struct introspect *i, const char *signature, const char **names, const char *direction) {
        int r;

        assert(i);
        assert(i->m.f);

        for (;;) {
                size_t l;

                if (!*signature)
                        return 0;

                r = signature_element_length(signature, &l);
                if (r < 0)
                        return r;

                fprintf(i->m.f, "   <arg type=\"%.*s\"", (int) l, signature);

                if (**names != '\0') {
                        fprintf(i->m.f, " name=\"%s\"", *names);
                        *names += strlen(*names) + 1;
                }

                if (direction)
                        fprintf(i->m.f, " direction=\"%s\"/>\n", direction);
                else
                        fputs("/>\n", i->m.f);

                signature += l;
        }
}

int introspect_write_interface(
                struct introspect *i,
                const char *interface_name,
                const sd_bus_vtable *v) {

        const sd_bus_vtable *vtable = ASSERT_PTR(v);
        const char *names = "";
        int r;

        assert(i);
        assert(i->m.f);
        assert(interface_name);

        r = set_interface_name(i, interface_name);
        if (r < 0)
                return r;

        for (; v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(vtable, v)) {

                /* Ignore methods, signals and properties that are
                 * marked "hidden", but do show the interface
                 * itself */

                if (v->type != _SD_BUS_VTABLE_START && (v->flags & SD_BUS_VTABLE_HIDDEN))
                        continue;

                switch (v->type) {

                case _SD_BUS_VTABLE_START:
                        if (v->flags & SD_BUS_VTABLE_DEPRECATED)
                                fputs("  <annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n", i->m.f);
                        break;

                case _SD_BUS_VTABLE_METHOD:
                        fprintf(i->m.f, "  <method name=\"%s\">\n", v->x.method.member);
                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.method.names);
                        introspect_write_arguments(i, strempty(v->x.method.signature), &names, "in");
                        introspect_write_arguments(i, strempty(v->x.method.result), &names, "out");
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </method>\n", i->m.f);
                        break;

                case _SD_BUS_VTABLE_PROPERTY:
                case _SD_BUS_VTABLE_WRITABLE_PROPERTY:
                        fprintf(i->m.f, "  <property name=\"%s\" type=\"%s\" access=\"%s\">\n",
                                v->x.property.member,
                                v->x.property.signature,
                                v->type == _SD_BUS_VTABLE_WRITABLE_PROPERTY ? "readwrite" : "read");
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </property>\n", i->m.f);
                        break;

                case _SD_BUS_VTABLE_SIGNAL:
                        fprintf(i->m.f, "  <signal name=\"%s\">\n", v->x.signal.member);
                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.signal.names);
                        introspect_write_arguments(i, strempty(v->x.signal.signature), &names, NULL);
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </signal>\n", i->m.f);
                        break;
                }

        }

        return 0;
}

int introspect_finish(struct introspect *i, char **ret) {
        assert(i);
        assert(i->m.f);

        assert_se(set_interface_name(i, NULL) >= 0);

        fputs("</node>\n", i->m.f);

        return memstream_finalize(&i->m, ret, NULL);
}

void introspect_done(struct introspect *i) {
        assert(i);

        /* Normally introspect_finish() does all the work, this is just a backup for error paths */

        memstream_done(&i->m);
        free(i->interface_name);
}
