/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-util.h"

int bus_property_get_activation_details(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ActivationDetails **details = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **pairs = NULL;
        int r;

        assert(reply);

        r = activation_details_append_pair(*details, &pairs);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_bus_message_append(reply, "(ss)", *key, *value);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}
