#ifndef BSDSIGNAL_H_
#define BSDSIGNAL_H_

#include <sys/time.h>
#include <sys/wait.h>

#include <signal.h>

#include "svc-config.h"

#ifndef _NSIG
#ifdef SIGRTMAX
#define _NSIG SIGRTMAX + 1
#else
#define _NSIG NSIG
#endif /* SIGRTMAX */
#endif /* _NSIG */

#ifdef SVC_PLATFORM_OpenBSD
int __thrsigdivert(sigset_t set, siginfo_t *info,
	const struct timespec *timeout);

#define sigtimedwait(set, info, timeout) __thrsigdivert(*set, info, timeout)
#define sigwaitinfo(set, info) sigtimedwait(set, info, NULL)
#endif /* SVC_PLATFORM_OpenBSD */

#ifndef HAVE_waitid
#define WSTOPPED 2 /* Report stopped child (same as WUNTRACED). */
#define WEXITED 4 /* Report dead child.  */
#define WCONTINUED 8 /* Report continued child.  */

typedef enum {
	P_ALL, /* Wait for any child.  */
	P_PID, /* Wait for specified process.  */
	P_PGID /* Wait for members of process group.  */
} idtype_t;

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
#endif /* HAVE_waitid */

siginfo_t waitstat_to_siginfo(pid_t pid, int waitstat);

#endif /* BSDSIGNAL_H_ */
