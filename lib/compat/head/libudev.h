#include "compat.h"

#ifdef Use_Devattr
#include <devattr.h>
#elif defined(Use_UDev)
#include <libudev.h>
#else
#error No UDev
#endif