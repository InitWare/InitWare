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

#include <ctype.h>

#include "fileio.h"
#include "util.h"

int get_parent_of_pid(pid_t pid, pid_t *_ppid) {
        int r;
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        long unsigned ppid;
        const char *p;

        assert(pid >= 0);
        assert(_ppid);

        if (pid == 0) {
                *_ppid = getppid();
                return 0;
        }

        p = procfs_file_alloca(pid, "stat");
        f = fopen(p, "re");
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                r = feof(f) ? -EIO : -errno;
                return r;
        }

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p,
                   " "
                   "%*c "  /* state */
                   "%lu ", /* ppid */
                   &ppid) != 1)
                return -EIO;

        if ((long unsigned) (pid_t) ppid != ppid)
                return -ERANGE;

        *_ppid = (pid_t) ppid;

        return 0;
}

int get_starttime_of_pid(pid_t pid, unsigned long long *st) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        const char *p;

        assert(pid >= 0);
        assert(st);

        if (pid == 0)
                p = "/proc/self/stat";
        else
                p = procfs_file_alloca(pid, "stat");

        f = fopen(p, "re");
        if (!f)
                return -errno;

        if (!fgets(line, sizeof(line), f)) {
                if (ferror(f))
                        return -errno;

                return -EIO;
        }

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p,
                   " "
                   "%*c " /* state */
                   "%*d " /* ppid */
                   "%*d " /* pgrp */
                   "%*d " /* session */
                   "%*d " /* tty_nr */
                   "%*d " /* tpgid */
                   "%*u " /* flags */
                   "%*u " /* minflt */
                   "%*u " /* cminflt */
                   "%*u " /* majflt */
                   "%*u " /* cmajflt */
                   "%*u " /* utime */
                   "%*u " /* stime */
                   "%*d " /* cutime */
                   "%*d " /* cstime */
                   "%*d " /* priority */
                   "%*d " /* nice */
                   "%*d " /* num_threads */
                   "%*d " /* itrealvalue */
                   "%llu " /* starttime */,
                   st) != 1)
                return -EIO;

        return 0;
}

int get_process_state(pid_t pid) {
        const char *p;
        char state;
        int r;
        _cleanup_free_ char *line = NULL;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r < 0)
                return r;

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " %c", &state) != 1)
                return -EIO;

        return (unsigned char) state;
}

int get_process_comm(pid_t pid, char **name) {
        const char *p;

        assert(name);
        assert(pid >= 0);

        if (pid == 0)
                p = "/proc/self/comm";
        else
                p = procfs_file_alloca(pid, "comm");

        return read_one_line_file(p, name);
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        char *r = NULL, *k;
        const char *p;
        int c;

        assert(line);
        assert(pid >= 0);

        if (pid == 0)
                p = "/proc/self/cmdline";
        else
                p = procfs_file_alloca(pid, "cmdline");

        f = fopen(p, "re");
        if (!f)
                return -errno;

        if (max_length == 0) {
                size_t len = 0, allocated = 0;

                while ((c = getc(f)) != EOF) {

                        if (!GREEDY_REALLOC(r, allocated, len + 2)) {
                                free(r);
                                return -ENOMEM;
                        }

                        r[len++] = isprint(c) ? c : ' ';
                }

                if (len > 0)
                        r[len - 1] = 0;

        } else {
                bool space = false;
                size_t left;

                r = new (char, max_length);
                if (!r)
                        return -ENOMEM;

                k = r;
                left = max_length;
                while ((c = getc(f)) != EOF) {

                        if (isprint(c)) {
                                if (space) {
                                        if (left <= 4)
                                                break;

                                        *(k++) = ' ';
                                        left--;
                                        space = false;
                                }

                                if (left <= 4)
                                        break;

                                *(k++) = (char) c;
                                left--;
                        } else
                                space = true;
                }

                if (left <= 4) {
                        size_t n = MIN(left - 1, 3U);
                        memcpy(k, "...", n);
                        k[n] = 0;
                } else
                        *k = 0;
        }

        /* Kernel threads have no argv[] */
        if (r == NULL || r[0] == 0) {
                char *t;
                int h;

                free(r);

                if (!comm_fallback)
                        return -ENOENT;

                h = get_process_comm(pid, &t);
                if (h < 0)
                        return h;

                r = strjoin("[", t, "]", NULL);
                free(t);

                if (!r)
                        return -ENOMEM;
        }

        *line = r;
        return 0;
}

int is_kernel_thread(pid_t pid) {
        const char *p;
        size_t count;
        char c;
        bool eof;
        FILE *f;

        if (pid == 0)
                return 0;

        assert(pid > 0);

        p = procfs_file_alloca(pid, "cmdline");
        f = fopen(p, "re");
        if (!f)
                return -errno;

        count = fread(&c, 1, 1, f);
        eof = feof(f);
        fclose(f);

        /* Kernel threads have an empty cmdline */

        if (count <= 0)
                return eof ? 1 : -errno;

        return 0;
}

int get_process_capeff(pid_t pid, char **capeff) {
        const char *p;

        assert(capeff);
        assert(pid >= 0);

        if (pid == 0)
                p = "/proc/self/status";
        else
                p = procfs_file_alloca(pid, "status");

        return get_status_field(p, "\nCapEff:", capeff);
}

int get_process_exe(pid_t pid, char **name) {
        const char *p;
        char *d;
        int r;

        assert(pid >= 0);
        assert(name);

        if (pid == 0)
                p = "/proc/self/exe";
        else
                p = procfs_file_alloca(pid, "exe");

        r = readlink_malloc(p, name);
        if (r < 0)
                return r;

        d = endswith(*name, " (deleted)");
        if (d)
                *d = '\0';

        return 0;
}

static int get_process_id(pid_t pid, const char *field, uid_t *uid) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        const char *p;

        assert(field);
        assert(uid);

        if (pid == 0)
                return getuid();

        p = procfs_file_alloca(pid, "status");
        f = fopen(p, "re");
        if (!f)
                return -errno;

        FOREACH_LINE(line, f, return -errno) {
                char *l;

                l = strstrip(line);

                if (startswith(l, field)) {
                        l += strlen(field);
                        l += strspn(l, WHITESPACE);

                        l[strcspn(l, WHITESPACE)] = 0;

                        return parse_uid(l, uid);
                }
        }

        return -EIO;
}

int get_process_uid(pid_t pid, uid_t *uid) {
        return get_process_id(pid, "Uid:", uid);
}

int get_process_gid(pid_t pid, gid_t *gid) {
        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        return get_process_id(pid, "Gid:", gid);
}

int getenv_for_pid(pid_t pid, const char *field, char **_value) {
        _cleanup_fclose_ FILE *f = NULL;
        char *value = NULL;
        int r;
        bool done = false;
        size_t l;
        const char *path;

        assert(pid >= 0);
        assert(field);
        assert(_value);

        if (pid == 0)
                path = "/proc/self/environ";
        else
                path = procfs_file_alloca(pid, "environ");

        f = fopen(path, "re");
        if (!f)
                return -errno;

        l = strlen(field);
        r = 0;

        do {
                char line[LINE_MAX];
                unsigned i;

                for (i = 0; i < sizeof(line) - 1; i++) {
                        int c;

                        c = getc(f);
                        if (_unlikely_(c == EOF)) {
                                done = true;
                                break;
                        } else if (c == 0)
                                break;

                        line[i] = c;
                }
                line[i] = 0;

                if (memcmp(line, field, l) == 0 && line[l] == '=') {
                        value = strdup(line + l + 1);
                        if (!value)
                                return -ENOMEM;

                        r = 1;
                        break;
                }

        } while (!done);

        *_value = value;
        return r;
}
