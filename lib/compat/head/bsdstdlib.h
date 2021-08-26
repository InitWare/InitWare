#ifndef BSDSTDLIB_H_
#define BSDSTDLIB_H_

#include <stdlib.h>

#include "compat.h"

#ifndef HAVE_reallocarray
void *reallocarray(void *optr, size_t nmemb, size_t size);
#endif

#endif /* BSDSTDLIB_H_ */
