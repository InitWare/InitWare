/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

/* Reset/clear ANSI styles */
#define ANSI_NORMAL "\x1B[0m"

/* Limits the use of ANSI colors to a subset. */
typedef enum ColorMode {
        /* No colors, monochrome output. */
        COLOR_OFF,

        /* All colors, no restrictions. */
        COLOR_ON,

        /* Only the base 16 colors. */
        COLOR_16,

        /* Only 256 colors. */
        COLOR_256,

        /* For truecolor or 24bit color support. */
        COLOR_24BIT,

        _COLOR_INVALID = -EINVAL,
} ColorMode;

ColorMode get_color_mode(void);

static inline bool colors_enabled(void) {
        /* Returns true if colors are considered supported on our stdout. */
        return get_color_mode() != COLOR_OFF;
}

#define DEFINE_ANSI_FUNC(name, NAME)                            \
        static inline const char *ansi_##name(void) {           \
                return colors_enabled() ? ANSI_##NAME : "";     \
        }

DEFINE_ANSI_FUNC(normal,            NORMAL);
