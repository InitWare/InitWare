/*******************************************************************

    LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

    (c) 2021 David Mackay
        All rights reserved.
*********************************************************************/

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

#include "compat.h"

#ifdef Sys_Plat_FreeBSD
/* KVM is platform-specific enough to not bother with CMake. */
#include <sys/user.h>
#endif

#ifdef Sys_Plat_DragonFlyBSD
#include <kinfo.h>
#endif

kvm_t *open_kvm();

extern kvm_t *g_kd;

#endif /* KVM_H_ */
