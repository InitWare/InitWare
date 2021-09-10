#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include "bsdglibc.h"

#ifndef SVC_HAVE_mempcpy
void *
mempcpy(void *dest, const void *src, size_t n)
{
	return (char *)memcpy(dest, src, n) + n;
}
#endif

#ifndef SVC_HAVE_getrandom
int
getrandom(void *buf, size_t buflen, unsigned int flags)
{
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NONBLOCK);

	assert(!(fd < 0));

	return read(fd, buf, buflen);
}
#endif
