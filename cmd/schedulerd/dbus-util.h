/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "unit.h"

int bus_property_get_activation_details(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

int bus_verify_manage_units_async_full(Unit *u, const char *verb, const char *polkit_message, sd_bus_message *call, sd_bus_error *error);
