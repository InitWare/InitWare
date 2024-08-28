/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "mountpoint-util.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "utf8.h"

static bool validate_api_vfs(const char *path, PathSimplifyWarnFlags flags) {

        assert(path);

        if ((flags & (PATH_CHECK_NON_API_VFS|PATH_CHECK_NON_API_VFS_DEV_OK)) == 0)
                return true;

        if (!path_below_api_vfs(path))
                return true;

        if (FLAGS_SET(flags, PATH_CHECK_NON_API_VFS_DEV_OK) && path_startswith(path, "/dev"))
                return true;

        return false;
}

int path_simplify_and_warn(
                char *path,
                PathSimplifyWarnFlags flags,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        bool fatal = flags & PATH_CHECK_FATAL;
        int level = fatal ? LOG_ERR : LOG_WARNING;

        assert(path);
        assert(!FLAGS_SET(flags, PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE));
        assert(!FLAGS_SET(flags, PATH_CHECK_NON_API_VFS | PATH_CHECK_NON_API_VFS_DEV_OK));
        assert(lvalue);

        if (!utf8_is_valid(path))
                return log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, path);

        if (flags & (PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE)) {
                bool absolute;

                absolute = path_is_absolute(path);

                if (!absolute && (flags & PATH_CHECK_ABSOLUTE))
                        return log_syntax(unit, level, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is not absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);

                if (absolute && (flags & PATH_CHECK_RELATIVE))
                        return log_syntax(unit, level, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);
        }

        path_simplify_full(path, flags & PATH_KEEP_TRAILING_SLASH ? PATH_SIMPLIFY_KEEP_TRAILING_SLASH : 0);

        if (!path_is_valid(path))
                return log_syntax(unit, level, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path has invalid length (%zu bytes)%s.",
                                  lvalue, strlen(path), fatal ? "" : ", ignoring");

        if (!path_is_normalized(path))
                return log_syntax(unit, level, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path is not normalized%s: %s",
                                  lvalue, fatal ? "" : ", ignoring", path);

        if (!validate_api_vfs(path, flags))
                return log_syntax(unit, level, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path is below API VFS%s: %s",
                                  lvalue, fatal ? ", refusing" : ", ignoring",
                                  path);

        return 0;
}
