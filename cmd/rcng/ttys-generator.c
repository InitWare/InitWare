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
 * ttys-generator - generate unitfiles from /etc/ttys
 *
 * ttys-generator -o /output/directory
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ttyent.h>
#include <unistd.h>


#include "mkdir.h"
#include "path-util.h"
#include "strv.h"

const char contents[] =
	"[Unit]\n"
	"Description=Console login on /dev/%s\n"
	"Documentation=man:agetty(8) man:iw_ttys-generator(8)\n"
	"After=systemd-user-sessions.service plymouth-quit-wait.service getty-pre.target\n"
	"After=rc-local.service\n"
	"\n"
	"Before=getty.target\n"
	"IgnoreOnIsolate=yes\n"
	"\n"
	"Conflicts=rescue.service\n"
	"Before=rescue.service\n"
	"\n"
	"[Service]\n"
	"ExecStart=-%s %s\n"
	"Type=idle\n"
	"Restart=always\n"
	"RestartSec=0\n"
	"UtmpIdentifier=%s\n"
	"TTYPath=/dev/%s\n"
	"TTYReset=yes\n"
	"TTYVHangup=yes\n"
	"TTYVTDisallocate=yes\n"
	"KillMode=process\n"
	"IgnoreSIGPIPE=no\n"
	"SendSIGHUP=yes\n"
	"\n"
	"[Install]\n"
	"WantedBy=getty.target\n"
	"\n";

static int mksymlink(const char *src, const char *slink)
{
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

static int generate_unit(struct ttyent *typ, const char *out_dir)
{
	char *out_name, *slink;
	FILE *out_file;
	int r;

	if ((typ->ty_status & TTY_ON) == 0 || typ->ty_name == NULL || typ->ty_getty == NULL ||
	    typ->ty_window)
		return 0;

	asprintf(&out_name, "%s/console-login-%s.service", out_dir, typ->ty_name);
	if (!out_name)
		return -ENOMEM;

	out_file = fopen(out_name, "w");
	if (!out_file) {
		free(out_name);
		return -errno;
	}

	fprintf(out_file, contents, typ->ty_name, typ->ty_getty, typ->ty_name, typ->ty_name, typ->ty_name);

	slink = strjoin(out_dir, "/default.target.wants/console-login-", typ->ty_name, ".service", NULL);

	if (!slink) {
		r = log_oom();
		goto finish;
	}

	r = mksymlink(out_name, slink);
	if (r < 0) {
		log_error("Failed to make default.target wants-link: %s\n", strerror(errno));
		r = -errno;
		goto finish;
	}

	free(slink);

	slink = strjoin(out_dir, "/default.target.after/console-login-", typ->ty_name, ".service", NULL);

	if (!slink) {
		r = log_oom();
		goto finish;
	}

	r = mksymlink(out_name, slink);
	if (r < 0) {
		log_error("Failed to make default.target after-link: %s\n", strerror(errno));
		r = -errno;
		goto finish;
	}

finish:
	fclose(out_file);
	free(slink);
	free(out_name);
	return r;
}

int main(int argc, char *argv[])
{
	struct ttyent *typ;

	if (argc != 4)
		errx(EXIT_FAILURE, "Usage: ttys-generator /early-dir /normal-dir /late-dir");

	while ((typ = getttyent()) != NULL) {
		generate_unit(typ, argv[1]);
	}
	(void) endttyent();
}