#include <string.h>

#include "compat.h"

#ifndef Have_mempcpy
void *mempcpy(void *dest, const void *src, size_t n) {
        return (char *) memcpy(dest, src, n) + n;
}
#endif