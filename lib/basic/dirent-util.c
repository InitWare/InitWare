#include <fcntl.h>
#include <sys/stat.h>

#include "dirent-util.h"
#include "path-util.h"
#include "stat-util.h"

int dirent_ensure_type(int dir_fd, struct dirent *de) {
        STRUCT_STATX_DEFINE(sx);
        int r;

        assert(dir_fd >= 0);
        assert(de);

        if (de->d_type != DT_UNKNOWN)
                return 0;

        if (dot_or_dot_dot(de->d_name)) {
                de->d_type = DT_DIR;
                return 0;
        }

        /* Let's ask only for the type, nothing else. */
        r = statx_fallback(dir_fd, de->d_name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_TYPE, &sx);
        if (r < 0)
                return r;

        assert(FLAGS_SET(sx.stx_mask, STATX_TYPE));
        de->d_type = IFTODT(sx.stx_mode);

        /* If the inode is passed too, update the field, i.e. report most recent data */
        if (FLAGS_SET(sx.stx_mask, STATX_INO))
                de->d_ino = sx.stx_ino;

        return 0;
}

struct dirent *readdir_ensure_type(DIR *d) {
        int r;

        assert(d);

        /* Like readdir(), but fills in .d_type if it is DT_UNKNOWN */

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de)
                        return NULL;

                r = dirent_ensure_type(dirfd(d), de);
                if (r >= 0)
                        return de;
                if (r != -ENOENT) {
                        errno = -r; /* We want to be compatible with readdir(), hence propagate error via errno here */
                        return NULL;
                }

                /* Vanished by now? Then skip immediately to next */
        }
}