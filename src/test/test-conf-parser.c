/***
  This file is part of systemd.

  Copyright 2015 Ronny Chevalier

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

#include "conf-parser.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "strv.h"
#include "util.h"

#define x10(x) x x x x x x x x x x
#define x100(x) x10(x10(x))
#define x1000(x) x10(x100(x))

static const char* const config_file[] = {
        "[Section]\n"
        "setting1=1\n",

        "[Section]\n"
        "setting1=1",        /* no terminating newline */

        "\n\n\n\n[Section]\n\n\n"
        "setting1=1",        /* some whitespace, no terminating newline */

        "[Section]\n"
        "[Section]\n"
        "setting1=1\n"
        "setting1=2\n"
        "setting1=1\n",      /* repeated settings */

        "[Section]\n"
        "setting1=1\\\n"     /* normal continuation */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "setting1=1\\\\\\\n" /* continuation with trailing escape symbols */
        "\\\\2\n",           /* note that C requires one level of escaping, so the
                              * parser gets "…1 BS BS BS NL BS BS 2 NL", which
                              * it translates into "…1 BS BS SP BS BS 2" */

        "\n[Section]\n\n"
        "setting1="          /* a line above LINE_MAX length */
        x1000("ABCD")
        "\n",

        "[Section]\n"
        "setting1="          /* a line above LINE_MAX length, with continuation */
        x1000("ABCD") "\\\n"
        "foobar",

        "[Section]\n"
        "setting1="          /* a line above the allowed limit: 9 + 1050000 + 1 */
        x1000(x1000("x") x10("abcde")) "\n",

        "[Section]\n"
        "setting1="          /* many continuation lines, together above the limit */
        x1000(x1000("x") x10("abcde") "\\\n") "xxx",
};

static void test_config_parse(unsigned i, const char *s) {
        char name[] = "/tmp/test-conf-parser.XXXXXX";
        int fd, r;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *setting1 = NULL;

        const ConfigTableItem items[] = {
                { "Section", "setting1",  config_parse_string,   0, &setting1},
                {}
        };

        log_info("== %s[%i] ==", __func__, i);

        fd = mkostemp_safe(name, O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se((size_t) write(fd, s, strlen(s)) == strlen(s));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(f = fdopen(fd, "r"));

        /*
        int config_parse(const char *unit,
                         const char *filename,
                         FILE *f,
                         const char *sections,
                         ConfigItemLookup lookup,
                         const void *table,
                         bool relaxed,
                         bool allow_include,
                         bool warn,
                         void *userdata)
        */

        r = config_parse(NULL, name, f,
                         "Section\0",
                         config_item_table_lookup, items,
                         false, false, true, NULL);

        switch (i) {
        case 0 ... 3:
                assert_se(r == 0);
                assert_se(streq(setting1, "1"));
                break;

        case 4:
                assert_se(r == 0);
                assert_se(streq(setting1, "1 2 3"));
                break;

        case 5:
                assert_se(r == 0);
                assert_se(streq(setting1, "1\\\\ \\\\2"));
                break;

        case 6:
                assert_se(r == 0);
                assert_se(streq(setting1, x1000("ABCD")));
                break;

        case 7:
                assert_se(r == 0);
                assert_se(streq(setting1, x1000("ABCD") " foobar"));
                break;

        case 8 ... 9:
                assert_se(r == -ENOBUFS);
                assert_se(setting1 == NULL);
                break;
        }
}

int main(int argc, char **argv) {
        unsigned i;

        for (i = 0; i < ELEMENTSOF(config_file); i++)
                test_config_parse(i, config_file[i]);

        return 0;
}
