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
#include <fcntl.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include "util.h"

static kvm_t *kd = NULL;

static struct kinfo_proc *get_pid_info(pid_t pid) {
        if (!kd)
                kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, "KVM Error");

        if (!kd)
                return NULL;
        else {
                int cnt;
                struct kinfo_proc *info = kvm_getprocs(kd, KERN_PROC_PID, pid, &cnt);
                assert(cnt == 1);
                return info;
        }
}


int get_parent_of_pid(pid_t pid, pid_t *_ppid) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info)
                return -errno;

        *_ppid = info->ki_ppid;

        return 0;
}

int get_process_state(pid_t pid) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info)
                return -errno;
        if (info->ki_stat == SZOMB)
                return 'Z';
        else
                return 'O'; /* TODO: extend. */
}

int get_process_comm(pid_t pid, char **name) {
        struct kinfo_proc *info = get_pid_info(pid);
        if (!info)
                return -errno;
        *name = strdup(info->ki_comm);
        if (!*name)
                return -ENOMEM;
        return 0;
}

int get_process_uid(pid_t pid, uid_t *uid) {
        struct kinfo_proc *info = get_pid_info(pid);
        return info->ki_ruid;
}

int get_process_gid(pid_t pid, gid_t *gid) {
        struct kinfo_proc *info = get_pid_info(pid);
        return info->ki_rgid;
}
