#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdglibc.h"
#include "bsdsignal.h"

#ifndef HAVE_mempcpy
void *
mempcpy(void *dest, const void *src, size_t n)
{
	return (char *)memcpy(dest, src, n) + n;
}
#endif

#ifndef SVC_HAVE_getrandom
int
getrandom(void *buf, size_t buflen, unsigned int flags)
{
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NONBLOCK);

	assert(!(fd < 0));

	return read(fd, buf, buflen);
}
#endif

#ifndef SVC_HAVE_lsb_basename
char *
lsb_basename(const char *filename)
{
	char *p = strrchr(filename, '/');
	return p ? p + 1 : (char *)filename;
}
#endif

siginfo_t
waitstat_to_siginfo(pid_t pid, int status)
{
	siginfo_t info;

	info.si_pid = pid;
	info.si_signo = SIGCHLD;

	if (WIFEXITED(status)) {
		info.si_code = CLD_EXITED;
		info.si_status = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		info.si_code = CLD_KILLED;
		info.si_status = WTERMSIG(status);
	}
#ifdef CLD_CONTINUED
	else if (WIFCONTINUED(status)) {
		info.si_code = CLD_CONTINUED;
		info.si_status = SIGCONT;
	}
#endif
	else if (WIFSTOPPED(status)) {
		info.si_code = CLD_STOPPED;
		info.si_status = WSTOPSIG(status);
	}

	return info;
}

#ifndef HAVE_waitid
int
waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	int status;
	int wpoptions = 0;

	assert(idtype == P_PID || idtype == P_ALL);

	if (options & WNOHANG)
		wpoptions = WNOHANG;

	for (;;) {
		pid_t pid = waitpid(idtype == P_PID ? id : -1, &status,
			wpoptions);

		if (pid < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (WIFCONTINUED(status) || WIFSTOPPED(status))
			continue;

		*infop = waitstat_to_siginfo(pid, status);

		return 0;
	}
}
#endif

#ifndef HAVE_strchrnul
/* from Rich Felker's muslibc */
#define ALIGN (sizeof(size_t))
#define ONES ((size_t)-1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) ((x)-ONES & ~(x)&HIGHS)

char *
strchrnul(const char *s, int c)
{
	size_t *w, k;

	c = (unsigned char)c;
	if (!c)
		return (char *)s + strlen(s);

	for (; (uintptr_t)s % ALIGN; s++)
		if (!*s || *(unsigned char *)s == c)
			return (char *)s;
	k = ONES * c;
	for (w = (void *)s; !HASZERO(*w) && !HASZERO(*w ^ k); w++)
		;
	for (s = (void *)w; *s && *(unsigned char *)s != c; s++)
		;
	return (char *)s;
}
#endif