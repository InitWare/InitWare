#ifndef BSDENDIAN_H_
#define BSDENDIAN_H_

#include "svc-config.h"

#include <stdint.h>

#ifdef HAVE_sys_endian_h
#include <sys/endian.h>
#elif defined(HAVE_endian_h)
#include <byteswap.h>
#include <endian.h>
#define bswap16 bswap_16
#define bswap32 bswap_32
#define bswap64 bswap_64
#elif defined(SVC_PLATFORM_MacOSX)
#include "macos/macendian.h"
#endif

#ifdef SVC_PLATFORM_OpenBSD
#define bswap16 swap16
#define bswap32 swap32
#define bswap64 swap64
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#define __BIG_ENDIAN _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif

#endif /* BSDENDIAN_H_ */
