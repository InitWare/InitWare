#ifndef COMPAT_H_
#define COMPAT_H_

#include <sys/types.h>
#include <sys/signal.h>
#include <errno.h>

#include "config.h"

#define POLKIT_AGENT_BINARY_PATH "@POLKIT_AGENT_BINARY_PATH@"

#ifdef Use_KQProc
#define Use_PTGroups true
#endif

#if defined(Use_Libudev) | defined(Use_Libdevattr)
#define Use_udev true
#endif

#ifdef Sys_Plat_FreeBSD
#define _PATH_UTMPX "/var/run/utx.active"
#endif

#ifndef Have___compar_fn_t
typedef int (*__compar_fn_t)(const void *, const void *);
#endif

#ifndef Have_environ
extern char **environ;
#endif

#ifndef Have_mempcpy
void *mempcpy(void *dest, const void *src, size_t n);
#endif

#ifndef Have_secure_getenv
#define secure_getenv getenv
#endif

#ifndef Have_statfs
#define statfs statvfs
#define fstatfs fstatvfs
#endif

#ifndef Have_program_invocation_short_name
#define program_invocation_short_name getprogname()
#endif

#ifndef Have_get_current_dir_name
#define get_current_dir_name() getcwd(NULL, 0)
#endif

#ifndef Have_strtonum
long long strtonum(const char *numstr, long long minval, long long maxval, const char **errstrp);
#endif

#ifndef EBADR
#define EBADR EBADF
#endif

#ifndef ETIME
#define ETIME ETIMEDOUT
#else
#define Have_ETIME
#endif

#ifndef ENODATA
#define ENODATA EBADF
#endif

#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

#ifdef Sys_Plat_Linux
#define Use_Mount
#define Use_Automount
#define Use_Swap
#define Use_Linprocfs
#endif

#ifdef Sys_Plat_Linux
#define Dgram_Credpass_Linux
#elif defined(Sys_Plat_NetBSD)
#define Dgram_Credpass_NetBSD
#elif defined(Sys_Plat_FreeBSD)
#define Dgram_Credpass_FreeBSD
#else
#define Dgram_Credpass_None
#endif

#ifndef strndupa
/*******************************************************************

	FOREIGN CODE BLOCK

    Origin: https://github.com/kraj/meta-musl/
    Licence: MIT
    Copyriight: Khem Raj

*********************************************************************/

#define strndupa(s, n)                                    \
	({                                                \
		const char *__old = (s);                  \
		size_t __len = strnlen(__old, (n));       \
		char *__new = (char *) alloca(__len + 1); \
		__new[__len] = '\0';                      \
		(char *) memcpy(__new, __old, __len);     \
	})
#endif

#ifndef strdupa
#define strdupa(s) strndupa(s, strlen(s))
#endif

#ifndef Have_waitid
#define WSTOPPED 2   /* Report stopped child (same as WUNTRACED). */
#define WEXITED 4    /* Report dead child.  */
#define WCONTINUED 8 /* Report continued child.  */

typedef enum {
	P_ALL, /* Wait for any child.  */
	P_PID, /* Wait for specified process.  */
	P_PGID /* Wait for members of process group.  */
} idtype_t;

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
#endif

#endif /* COMPAT_H_ */
