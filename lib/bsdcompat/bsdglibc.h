#ifndef BSDGLIBC_H_
#define BSDGLIBC_H_

#include <sys/types.h>

#include <libgen.h>
#undef basename
#include <stdint.h>

#include "bsderrno.h"
#include "svc-config.h"

#ifndef HAVE_strtod_l
#define strtod_l(nptr, endptr, locale) strtod(nptr, endptr)
#endif

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
#endif

#ifndef CLOCK_BOOTTIME_ALARM
#define CLOCK_BOOTTIME_ALARM CLOCK_BOOTTIME
#define CLOCK_REALTIME_ALARM CLOCK_REALTIME
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
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
#else
#define bsd_reboot reboot
#endif

#ifndef SVC_HAVE_lsb_basename
char *lsb_basename(const char *path);
#else
#define lsb_basename(path) basename(path)
#endif

#ifndef SVC_HAVE_getrandom
int getrandom(void *buf, size_t buflen, unsigned int flags);
#endif

#ifdef SVC_PLATFORM_NetBSD
#define NOFOLLOW_SYMLINK_ERRNO EFTYPE
#elif defined(SVC_PLATFORM_FreeBSD)
#define NOFOLLOW_SYMLINK_ERRNO EMLINK
#else
#define NOFOLLOW_SYMLINK_ERRNO ELOOP
#endif

#ifdef SVC_PLATFORM_NetBSD
#define ppoll pollts
#endif

#ifndef HAVE_strchrnul
char *strchrnul(const char *s, int c);
#endif

#endif /* BSDGLIBC_H_ */
