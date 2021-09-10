#ifndef BSDSTATFS_H_
#define BSDSTATFS_H_

#include "svc-config.h"

#if defined(SVC_HAVE_statfs)
#include <sys/statfs.h>
#elif defined(SVC_HAVE_statvfs)
#include <sys/statvfs.h>

#define statfs statvfs
#define fstatfs fstatvfs
#else
#error "Need statfs or statvfs"
#endif

#endif /* BSDSTATFS_H_ */
