/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */
/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#ifndef KVM_H_
#define KVM_H_

/* needed for NetBSD */
#define _KMEMUSER
#include <sys/types.h>
#undef _KMEMUSER
#include <sys/param.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <kvm.h>

#include "svc-config.h"

#ifdef SVC_PLATFORM_FreeBSD
#include <sys/user.h>
#endif

#ifdef SVC_PLATFORM_DragonFlyBSD
#include <kinfo.h>
#endif

kvm_t *open_kvm();

extern kvm_t *g_kd;

#endif /* KVM_H_ */
