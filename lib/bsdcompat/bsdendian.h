#ifndef BSDENDIAN_H_
#define BSDENDIAN_H_

#include "svc-config.h"

#ifdef HAVE_sys_endian_h
#include <sys/endian.h>
#elif defined(HAVE_endian_h)
#include <byteswap.h>
#include <endian.h>
#elif defined(SVC_PLATFORM_MacOSX)
#include "macos/macendian.h"
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#define __BIG_ENDIAN _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif

#endif /* BSDENDIAN_H_ */
