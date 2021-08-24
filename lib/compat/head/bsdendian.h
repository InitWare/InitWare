#ifndef BSDENDIAN_H_
#define BSDENDIAN_H_

#include "compat.h"

#ifdef Have_sys_endian_h
#include <sys/endian.h>
#elif defined(Have_endian_h)
#include <byteswap.h>
#include <endian.h>
#elif defined(Sys_Plat_MacOS)
#include "macos/macendian.h"
#endif

#endif /* BSDENDIAN_H_ */
