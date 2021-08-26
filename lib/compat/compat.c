/*
 *	LICENCE NOTICE (Combined)
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 * In addition, portions of such source code were derived from other software
 * under licence from their copyright holders.
 *
 *	Copyright Notice
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */
/*
 * Copyright (c) 2008 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/wait.h>

#include <assert.h>
#include <string.h>

#include "bsdstdlib.h"
#include "compat.h"

#ifndef Have_mempcpy
void *mempcpy(void *dest, const void *src, size_t n)
{
	return (char *) memcpy(dest, src, n) + n;
}
#endif

#ifndef Have_waitid
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	int status;
	int wpoptions = 0;

	assert(idtype == P_PID || idtype == P_ALL);

	if (options & WNOHANG)
		wpoptions = WNOHANG;

	for (;;) {
		pid_t pid = waitpid(idtype == P_PID ? id : -1, &status, wpoptions);

		if (pid < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (WIFCONTINUED(status)|| WIFSTOPPED(status))
			continue;

		infop->si_pid = pid;
		infop->si_signo = SIGCHLD;

		if (WIFEXITED(status)) {
			infop->si_code = CLD_EXITED;
			infop->si_status = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			infop->si_code = CLD_KILLED;
			infop->si_status = WTERMSIG(status);
		}

		return 0;
	}
}
#endif

#ifndef HAVE_reallocarray
#define MUL_NO_OVERFLOW ((size_t) 1 << (sizeof(size_t) * 4))

void *reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) && nmemb > 0 &&
	    SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}
#endif