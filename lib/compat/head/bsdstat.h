#ifndef BSDSTAT_H_
#define BSDSTAT_H_

#include <sys/stat.h>

#include "config.h"

#ifdef Sys_Plat_MacOS
#define st_ctim st_ctimespec
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#endif

#endif /* BSDSTAT_H_ */
