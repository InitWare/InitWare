/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>

typedef enum ImageClass {
        IMAGE_MACHINE,
        IMAGE_PORTABLE,
        IMAGE_SYSEXT,
        _IMAGE_CLASS_EXTENSION_FIRST = IMAGE_SYSEXT,  /* First "extension" image type, so that we can easily generically iterate through them */
        IMAGE_CONFEXT,
        _IMAGE_CLASS_EXTENSION_LAST = IMAGE_CONFEXT,  /* Last "extension image type */
        _IMAGE_CLASS_MAX,
        _IMAGE_CLASS_INVALID = -EINVAL,
} ImageClass;

int parse_extension_release_sentinel(const char *root, ImageClass image_class, bool relax_extension_release_check, const char *extension, ...) _sentinel_;
#define parse_extension_release(root, image_class, extension, relax_extension_release_check, ...) \
        parse_extension_release_sentinel(root, image_class, relax_extension_release_check, extension, __VA_ARGS__, NULL)
#define parse_os_release(root, ...)                                     \
        parse_extension_release_sentinel(root, _IMAGE_CLASS_INVALID, false, NULL, __VA_ARGS__, NULL)
