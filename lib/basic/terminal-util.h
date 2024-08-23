/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Smaller InitWare version, we add as needed here
#pragma once

#include <stdbool.h>

/* Regular colors */
#define ANSI_BLACK   "\x1B[0;30m" /* Some type of grey usually. */
#define ANSI_RED     "\x1B[0;31m"
#define ANSI_GREEN   "\x1B[0;32m"
#define ANSI_YELLOW  "\x1B[0;33m"
#define ANSI_BLUE    "\x1B[0;34m"
#define ANSI_MAGENTA "\x1B[0;35m"
#define ANSI_CYAN    "\x1B[0;36m"
#define ANSI_WHITE   "\x1B[0;37m" /* This is actually rendered as light grey, legible even on a white
                                   * background. See ANSI_HIGHLIGHT_WHITE for real white. */

#define ANSI_BRIGHT_BLACK   "\x1B[0;90m"
#define ANSI_BRIGHT_RED     "\x1B[0;91m"
#define ANSI_BRIGHT_GREEN   "\x1B[0;92m"
#define ANSI_BRIGHT_YELLOW  "\x1B[0;93m"
#define ANSI_BRIGHT_BLUE    "\x1B[0;94m"
#define ANSI_BRIGHT_MAGENTA "\x1B[0;95m"
#define ANSI_BRIGHT_CYAN    "\x1B[0;96m"
#define ANSI_BRIGHT_WHITE   "\x1B[0;97m"

#define ANSI_GREY    "\x1B[0;38;5;245m"

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

bool getenv_terminal_is_dumb(void);
bool terminal_is_dumb(void);
ColorMode get_color_mode(void);

static inline bool colors_enabled(void) {
        /* Returns true if colors are considered supported on our stdout. */
        return get_color_mode() != COLOR_OFF;
}

#define DEFINE_ANSI_FUNC(name, NAME)                            \
        static inline const char *ansi_##name(void) {           \
                return colors_enabled() ? ANSI_##NAME : "";     \
        }

#define DEFINE_ANSI_FUNC_256(name, NAME, FALLBACK)             \
        static inline const char *ansi_##name(void) {          \
                switch (get_color_mode()) {                    \
                        case COLOR_OFF: return "";             \
                        case COLOR_16: return ANSI_##FALLBACK; \
                        default : return ANSI_##NAME;          \
                }                                              \
        }

DEFINE_ANSI_FUNC(normal,            NORMAL);
DEFINE_ANSI_FUNC_256(grey,          GREY, BRIGHT_BLACK);
