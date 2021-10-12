#ifndef BSDCAPABILITY_H_
#define BSDCAPABILITY_H_

#include "svc-config.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/capability.h>
#ifndef SVC_HAVE_libcap
#endif
#else
/* on non-Linux, those aren't meaningfully used; so define them to 0 */
#define CAP_SYS_BOOT 0
#define CAP_SYS_ADMIN 0
#define CAP_KILL 0
#endif

#endif /* BSDCAPABILITY_H_ */
