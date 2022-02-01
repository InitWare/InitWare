/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2010-2021 the systemd developers */
#ifndef ERRNO_UTIL_H_
#define ERRNO_UTIL_H_

#include "util.h"

/* Hint #1: ENETUNREACH happens if we try to connect to "non-existing" special IP addresses, such as ::5.
 *
 * Hint #2: The kernel sends e.g., EHOSTUNREACH or ENONET to userspace in some ICMP error cases.  See the
 *          icmp_err_convert[] in net/ipv4/icmp.c in the kernel sources.
 *
 * Hint #3: When asynchronous connect() on TCP fails because the host never acknowledges a single packet,
 *          kernel tells us that with ETIMEDOUT, see tcp(7). */
static inline bool ERRNO_IS_DISCONNECT(int r) {
        return IN_SET(abs(r),
                      ECONNABORTED,
                      ECONNREFUSED,
                      ECONNRESET,
                      EHOSTDOWN,
                      EHOSTUNREACH,
                      ENETDOWN,
                      ENETRESET,
                      ENETUNREACH,
                      ENONET,
                      ENOPROTOOPT,
                      ENOTCONN,
                      EPIPE,
                      EPROTO,
                      ESHUTDOWN,
                      ETIMEDOUT);
}

/* Transient errors we might get on accept() that we should ignore. As per error handling comment in
 * the accept(2) man page. */
static inline bool ERRNO_IS_ACCEPT_AGAIN(int r) {
        return ERRNO_IS_DISCONNECT(r) ||
                IN_SET(abs(r),
                       EAGAIN,
                       EINTR,
                       EOPNOTSUPP);
}

/* Resource exhaustion, could be our fault or general system trouble */
static inline bool ERRNO_IS_RESOURCE(int r) {
        return IN_SET(abs(r),
                      EMFILE,
                      ENFILE,
                      ENOMEM);
}

/* Seven different errors for "operation/system call/ioctl/socket feature not supported" */
static inline bool ERRNO_IS_NOT_SUPPORTED(int r) {
        return IN_SET(abs(r),
                      EOPNOTSUPP,
                      ENOTTY,
                      ENOSYS,
                      EAFNOSUPPORT,
                      EPFNOSUPPORT,
                      EPROTONOSUPPORT,
                      ESOCKTNOSUPPORT);
}

/* Two different errors for access problems */
static inline bool ERRNO_IS_PRIVILEGE(int r) {
        return IN_SET(abs(r),
                      EACCES,
                      EPERM);
}

/* Three difference errors for "not enough disk space" */
static inline bool ERRNO_IS_DISK_SPACE(int r) {
        return IN_SET(abs(r),
                      ENOSPC,
                      EDQUOT,
                      EFBIG);
}



#endif /* ERRNO_UTIL_H_ */
