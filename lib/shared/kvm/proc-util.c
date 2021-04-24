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

#include <assert.h>

#include "kvm.h"
#include "strv.h"
#include "util.h"

#if defined(Sys_Plat_NetBSD)
#        define kinfo_proc kinfo_proc2
#        define kvm_getargv kvm_getargv2
#        define kvm_getprocs(kd, op, arg, cnt) kvm_getproc2(kd, op, arg, sizeof(struct kinfo_proc2), cnt)
#elif defined(Sys_Plat_DragonFlyBSD)
#        define p_ppid kp_ppid
#        define p_stat kp_stat
#        define p_comm kp_comm
#        define p_ruid kp_ruid
#        define p_rgid kp_rgid
#elif defined(Sys_Plat_FreeBSD)
#        define p_ppid ki_ppid
#        define p_stat ki_stat
#        define p_comm ki_comm
#        define p_ruid ki_ruid
#        define p_rgid ki_rgid
#else
#        error "Unsupported platform- please port"
#endif

kvm_t *g_kd = NULL;

kvm_t *open_kvm() {
        if (!g_kd)
#if defined(Sys_Plat_FreeBSD) || defined(Sys_Plat_DragonFlyBSD)
                g_kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, "KVM Error");
#elif defined(Sys_Plat_NetBSD) || defined(Sys_Plat_OpenBSD)
                g_kd = kvm_open(NULL, NULL, NULL, KVM_NO_FILES, "KVM Error");
#else
#        error "Unsupported platform - please port"
#endif
        return g_kd;
}

static struct kinfo_proc *get_pid_info(pid_t pid) {
        if (!open_kvm())
                return NULL;
        else {
                int cnt;
                struct kinfo_proc *info;

                info = kvm_getprocs(g_kd, KERN_PROC_PID, pid, &cnt);
                if (!cnt) /* maybe already wait()'d on */
                        return NULL;

                return info;
        }
}


int get_parent_of_pid(pid_t pid, pid_t *_ppid) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info)
                return -errno;

        *_ppid = info->p_ppid;

        return 0;
}

int get_process_state(pid_t pid) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info)
                return -errno;
        if (info->p_stat == SZOMB)
                return 'Z';
        else
                return 'O'; /* TODO: extend. */
}

int get_process_comm(pid_t pid, char **name) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info) {
                *name = strdup("invalid-pid");
                if (!*name)
                        return -ENOMEM;
                else
                        return -errno;
        }
        *name = strdup(info->p_comm);
        if (!*name)
                return -ENOMEM;
        return 0;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        struct kinfo_proc *info;
        char **argv;

        info = get_pid_info(pid);

        if (!info) {
                *line = strdup("[invalid-pid]");
                if (!*line)
                        return -ENOMEM;
                else
                        return -errno;
        }

        argv = kvm_getargv(g_kd, info, max_length);
        if (!argv)
                return -ENOMEM;

        *line = strv_join(argv, " ");
        if (!*line)
                return -ENOMEM;

        return 0;
}

int get_process_uid(pid_t pid, uid_t *uid) {
        struct kinfo_proc *info = get_pid_info(pid);
        return info->p_ruid;
}

int get_process_gid(pid_t pid, gid_t *gid) {
        struct kinfo_proc *info = get_pid_info(pid);
        return info->p_rgid;
}
