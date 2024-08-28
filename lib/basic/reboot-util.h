/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

bool reboot_parameter_is_valid(const char *parameter);
int update_reboot_parameter_and_warn(const char *parameter, bool keep);
