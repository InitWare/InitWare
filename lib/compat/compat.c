#include <sys/wait.h>

#include <assert.h>
#include <string.h>

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
