#ifndef BSDCDEFS_H_
#define BSDCDEFS_H_

#include "svc-config.h"

#include <sys/types.h>

#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#define __END_DECLS
#endif

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(unsigned long)(const void *)(a))
#endif

#endif /* BSDCDEFS_H_ */
