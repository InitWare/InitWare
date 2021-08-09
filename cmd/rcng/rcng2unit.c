/*******************************************************************

        LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

        Copyright Notice

    (c) 2021 David Mackay
        All rights reserved.

*********************************************************************/
/**
 * rcng2unit - generate unitfiles from a Mewburn RC script.
 *
 * rcng2unit [-e] [-s] -o /output/directory /etc/rc.d/script
 *
 * -e: Add the generated unit-file as a dependency of rcng-scripts.target
 * -n: Generate a no-op unit file (i.e. for very early startup scripts ran
 *     outwith initware.)
 */

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include "install.h"
#include "mkdir.h"
#include "path-util.h"
#include "strv.h"

typedef struct RcNgService {
        const char *name;
        /* path to original rc script */
        const char *src_path;
        /*
         * All entries for the PROVIDE line. The first is usually identical to the
         * basename of the script, which is stored in @name. We therefore test
         * whether a provide entry is equal to @name before we generate a symlink.
         */
        char **provides;
        char **requires;
        char **before;
} RcNgService;

static int parse_rcscript(FILE *rcscript, RcNgService *svc) {
        int r;

        while (!feof(rcscript)) {
                char l[LINE_MAX], *t;

                if (!fgets(l, sizeof(l), rcscript)) {
                        if (feof(rcscript))
                                break;

                        log_error("Failed to read RC script '%s': %m", svc->src_path);
                        return -errno;
                }

                t = strstrip(l);
                if (*t != '#')
                        continue;

                t += 2;

                if (strneq(t, "PROVIDE:", 8))
                        svc->provides = strv_split(t + 9, " ");
                else if (strneq(t, "REQUIRE:", 8))
                        svc->requires = strv_split(t + 9, " ");
                else if (strneq(t, "BEFORE:", 7))
                        svc->before = strv_split(t + 8, " ");
        }

        return 0;
}

static int emit_name_list(FILE *out_f, char **names, bool append_svc) {
        char **el;

        STRV_FOREACH (el, names) {
                if (el != names) /* space before, except for first entry */
                        fputs(" ", out_f);
                if (append_svc) {
                        strextend(el, ".service", NULL);
                        if (!*el)
                                return log_oom();
                }
                fputs(*el, out_f);
        }

        return 0;
}

static int do_wanted_symlinks(const char *name, const char *out_name, const char *out_dir, char **wanted_bys) {
        char **wanted_by;
        int r;

        STRV_FOREACH (wanted_by, wanted_bys) {
                char *slink;

                slink = strjoin(out_dir, "/", *wanted_by, ".wants/", name, ".service", NULL);
                if (!slink) {
                        r = log_oom();
                        goto finish;
                }

                mkdir_parents_label(slink, 0755);
                r = symlink(out_name, slink);
                if (r < 0) {
                        if (errno == EEXIST)
                                r = 0;
                        else
                                log_error(
                                        "Failed to create symlink with source %s named %s: %m; "
                                        "continuing with other symlinks.",
                                        out_name,
                                        slink);
                }

                free(slink);
        }

finish:
        return -r;
}

static int do_provides(const char *name, const char *out_name, const char *out_dir, char **provides) {
        char **provide;
        int r;

        STRV_FOREACH (provide, provides) {
                char *slink;

                if (streq(*provide, name)) /* don't symlink default name */
                        continue;
                slink = strjoin(out_dir, "/", *provide, ".service", NULL);
                if (!slink)
                        return log_oom();

                r = symlink(out_name, slink);
                if (r < 0) {
                        if (errno == EEXIST)
                                r = 0;
                        else
                                log_error(
                                        "Failed to create symlink with source %s named %s: %m; "
                                        "continuing with any other symlinks.",
                                        out_name,
                                        slink);
                }
                free(slink);
        }


        return 0;
}

static int mksymlink(const char *src, const char *slink) {
        int r;

        mkdir_parents_label(slink, 0755);

        r = symlink(src, slink);
        if (r < 0 && errno == EEXIST)
                return 0;
        else if (r == 0)
                return 0;
        else
                return -errno;
}

static int emit_units(const char *out_dir, RcNgService *svc, bool wanted_by_default) {
        char *out_name;
        FILE *out_f;
        char *slink = NULL;
        int r;

        out_name = strjoin(out_dir, "/", svc->name, ".service", NULL);

        if (!out_name) {
                r = log_oom();
                goto finish;
        }

        unlink(out_name);

        out_f = fopen(out_name, "wxe");

        if (!out_f) {
                log_error("Failed to open %s for writing: %m\n", out_name);
                return -errno;
        }

        fprintf(out_f,
                "# Automatically generated by the InitWare Mewburn RC Script Converter\n\n"
                "[Unit]\n"
                "Documentation=man:svc_rcng(8)\n"
                "SourcePath=%s\n"
                "Description=Mewburn RC script %s\n",
                svc->src_path,
                svc->name);

        if (svc->requires) {
                fprintf(out_f, "Wants="); /* we downgrade Requires. */
                r = emit_name_list(out_f, svc->requires, true);
                if (r < 0)
                        goto finish;
                fputs("\n", out_f);
                fprintf(out_f, "After=");
                r = emit_name_list(out_f, svc->requires, false);
                if (r < 0)
                        goto finish;
                fputs("\n", out_f);
        }

        if (svc->before) {
                fprintf(out_f, "Before=");
                r = emit_name_list(out_f, svc->before, true);
                if (r < 0)
                        goto finish;
                r = do_wanted_symlinks(svc->name, out_name, out_dir, svc->before);
                fputs("\n", out_f);
        }

        if (svc->provides) {
                r = do_provides(svc->name, out_name, out_dir, svc->provides);
                if (r < 0)
                        goto finish;
                fputs("\n", out_f);
        }

	fprintf(out_f,
		"[Service]\n"
		"StandardOutput=tty\n"
		"Type=oneshot\n"
		"RemainAfterExit=yes\n"
		"ExecStart=/bin/sh %s faststart\n"
		"ExecStop=/bin/sh %s stop\n",
		svc->src_path,
		svc->src_path);

	fputc('\n', out_f);

        if (wanted_by_default) {
		slink = strjoin(out_dir, "/rcng-scripts.target.wants/", svc->name, ".service", NULL);

		if (!slink) {
                        r = log_oom();
                        goto finish;
                }

                r = mksymlink(out_name, slink);
                if (r < 0) {
			log_error("Failed to make rcng-scripts.target wants-link: %s\n",
			    strerror(errno));
			r = -errno;
                        goto finish;
                }

                free(slink);

		slink = strjoin(out_dir, "/rcng-scripts.target.after/", svc->name, ".service", NULL);

		if (!slink) {
                        r = log_oom();
                        goto finish;
                }

                r = mksymlink(out_name, slink);
                if (r < 0) {
			log_error("Failed to make rcng-scripts.target after-link: %s\n",
			    strerror(errno));
			r = -errno;
                        goto finish;
                }
        }

finish:
        free(slink);
        fclose(out_f);

        return r;
}

int main(int argc, char *argv[]) {
        FILE *rcscript;
        char retcode;
        const char *name;
        int r;
        RcNgService *svc;

        if (argc != 4)
                errx(EXIT_FAILURE, "Usage: %s /path/to/rc.d/service /path/to/out.service [yes|no]", argv[0]);

        rcscript = fopen(argv[1], "r");
        if (!rcscript)
                err(EXIT_FAILURE, "Failed to open RC script %s", argv[1]);

        name = path_get_file_name(argv[1]);

        svc = new0(RcNgService, 1);
        svc->name = name;
        svc->src_path = argv[1];

        r = parse_rcscript(rcscript, svc);
        if (r < 0) {
                log_error("Failed to parse RC script: %s\n", strerror(-r));
                goto finish;
        }

        r = emit_units(argv[2], svc, streq(argv[3], "yes") ? true : false);
        if (r < 0) {
                log_error("Failed to emit units for RC script: %s\n", strerror(-r));
        }

finish:
        strv_free(svc->before);
        strv_free(svc->provides);
        strv_free(svc->requires);
        free(svc);
        return -r;
}
