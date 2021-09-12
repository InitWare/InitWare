#ifndef BSDGLIBC_H_
#define BSDGLIBC_H_

#include <sys/types.h>

#include <libgen.h>
#include <stdint.h>

#include "svc-config.h"

#ifndef Have___compar_fn_t
typedef int (*__compar_fn_t)(const void *, const void *);
#endif

#ifndef strndupa
/*******************************************************************
    Origin: https://github.com/kraj/meta-musl/
    Licence: MIT
    Copyright: Khem Raj
*********************************************************************/
#define strndupa(s, n)                                                         \
	({                                                                     \
		const char *__old = (s);                                       \
		size_t __len = strnlen(__old, (n));                            \
		char *__new = (char *)alloca(__len + 1);                       \
		__new[__len] = '\0';                                           \
		(char *)memcpy(__new, __old, __len);                           \
	})
#endif

#ifndef strdupa
#define strdupa(s) strndupa(s, strlen(s))
#endif

#ifndef HAVE_secure_getenv
#define secure_getenv getenv
#endif

#ifndef SVC_HAVE_program_invocation_short_name
#define program_invocation_short_name getprogname()
#endif

#ifndef SVC_HAVE_get_current_dir_name
#define get_current_dir_name() getcwd(NULL, 0)
#endif

#ifndef HAVE_canonicalize_file_name
#define canonicalize_file_name(filename) realpath(filename, NULL)
#endif

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#define CLOCK_BOOTTIME_ALARM CLOCK_MONOTONIC
#define CLOCK_REALTIME_ALARM CLOCK_REALTIME
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef EREMOTEIO
#define EREMOTEIO EIO
#endif

#ifndef EDEADLOCK
#define EDEADLOCK ELOOP
#endif

#ifndef EBADR
#define EBADR EBADF
#endif

#ifndef ENONET
#define ENONET ENOTCONN
#endif

#ifndef HAVE_mempcpy
void *mempcpy(void *dest, const void *src, size_t n);
#endif

#ifndef HAVE_gettid
#define gettid getpid
#endif

#ifndef SVC_HAVE_environ
extern char **environ;
#endif

#ifdef SVC_PLATFORM_NetBSD
#define bsd_reboot(how) reboot(how, "")
#define setresgid(r, e, s) setgid(r)
#define setresuid(r, e, s) setuid(r)
#endif

#ifndef SVC_HAVE_lsb_basename
#define lsb_basename(path) basename((char *)path)
#else
#define lsb_basename(path) basename(path)
#endif

#ifndef SVC_HAVE_getrandom
int getrandom(void *buf, size_t buflen, unsigned int flags);
#endif

#endif /* BSDGLIBC_H_ */
