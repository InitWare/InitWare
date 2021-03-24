#include "compat.h"

#ifdef Use_libdevattr
#include <devattr.h>
#elif defined(Use_udev)
#include_next <libudev.h>
#else
#error No UDev
#endif