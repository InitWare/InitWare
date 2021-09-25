#ifndef BSDERRNO_H_
#define BSDERRNO_H_

#include <errno.h>

/* missing errnos */

#ifndef ENODATA
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

#ifndef ENOLINK
#define ENOLINK ENOENT
#else
#define HAVE_ENOLINK
#endif

#endif /* BSDERRNO_H_ */
