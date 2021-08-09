/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#ifndef MICROHTTPD_UTIL_H_
#define MICROHTTPD_UTIL_H_

#include <stdarg.h>

#include "macro.h"

void microhttpd_logger(void *arg, const char *fmt, va_list ap) _printf_attr_(2, 0);

#endif /* MICROHTTPD_UTIL_H_ */
