#include <string.h>

#include "bsdglibc.h"

#ifndef SVC_HAVE_mempcpy
void *mempcpy(void *dest, const void *src, size_t n)
{
	return (char *) memcpy(dest, src, n) + n;
}
#endif