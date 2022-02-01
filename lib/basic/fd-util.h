#ifndef FD_UTIL_H_
#define FD_UTIL_H_

#include "util.h"

/* Like TAKE_PTR() but for file descriptors, resetting them to -1 */
#define TAKE_FD(fd)                             \
        ({                                      \
                int _fd_ = (fd);                \
                (fd) = -1;                      \
                _fd_;                           \
        })

#endif /* FD_UTIL_H_ */
