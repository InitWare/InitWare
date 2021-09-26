#ifndef BSDGLOB_H_
#define BSDGLOB_H_

#include "svc-config.h"

#if !defined(HAVE_GLOB_ALTDIRFUNC) || !defined(HAVE_GLOB_BRACE)
#define BUILD_GLOB
#include "netbsd/glob.h"
#else
#include <glob.h>
#endif

#endif /* BSDGLOB_H_ */
