#ifndef BSDERRNO_H_
#define BSDERRNO_H_

#include <errno.h>

/* missing errnos */

#ifndef ENDOATA
#define ENODATA EBADF
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

#ifndef ETIME
#define ETIME ETIMEDOUT
#else
#define HAVE_ETIME
#endif

#endif /* BSDERRNO_H_ */
