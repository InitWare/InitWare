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
/**
 * These are Process Tracking Groups, or PTGroups - groups of processes and/or
 * other groups, whose member processes may be iterated through (recursively if
 * desired). Notification may be made when a PTGroup becomes empty.
 *
 * PTGroups are a very simple abstraction layer which require an underlying
 * mechanism to work:
 *
 * - You need to have a means of tracking at least those processes you are
 *   interested in, such that you are notifide when those processes fork or
 *   exit.
 * - The mechanism should automatically track newly-forked processes to obviate
 *   a race to watch them before parent or child exits.
 *
 * The Kernel Queues event system of the BSD systems has an almost perfect such
 * mechanism: the PROC event filter. Its only weakness is that, in a situation
 * of low memory, it may fail to attach to a newly-forked process, with
 * NOTE_TRACKERR returned.
 *
 * It is also important to note that, more generally to this implementation,
 * memory allocation failure breaks tracking by simple dint of making it
 * impossible to record which processes we even track.
 */

#ifndef PTGROUP_H_
#define PTGROUP_H_

#include "compat.h"
#include "fdset.h"
#include "set.h"

typedef struct Manager Manager;
typedef struct Unit Unit;

typedef struct PTGroup PTGroup;
typedef struct PTManager PTManager;

typedef struct cJSON cJSON;

struct PTGroup {
	/* associated manager */
	Manager *manager;

	/* name of this group */
	char *name;

	/* full name of this group */
	char *full_name;

	/*
	 * The parent group, or NULL if this is the root group. (If it is the
	 * root group, then this is actually a PTManager object.)
	 */
	PTGroup *parent;

	/* list of all groups belonging directly to this group */
	Set *groups;

	/* set of all PIDs belonging directly to this group */
	Set *processes;
};

struct PTManager {
	PTGroup group;
};

/**
 * Create a new PTGroup with the given name and parent group.
 *
 * The PTGroup object takes ownership of \p name.
 *
 * @returns 0 if allocation fails.
 */
PTGroup *ptgroup_new(PTGroup *parent, char *name);

/**
 * Remove all references to a PTGroup, recursively invoking this function on all
 * child PTGroups, then free the group.
 *
 * References are deleted from:
 * - the parent group;
 * - the ptgroup-to-unit hashmap of the manager;
 * - the unit mapped to this ptgroup by that hashmap.
 */
void ptg_release(PTGroup *grp);

/**
 * Attach a PID to a PTGroup. If attached to an existing PTGroup, the PID is
 * moved.
 *
 * Driver-specific, no agnostic implementation. Returns -errno on failure.
 */
int ptgroup_attach(PTGroup *grp, PTManager *ptm, pid_t pid);

/** Attach a set of PIDs to a PTGroup. */
int ptgroup_attach_many(PTGroup *grp, PTManager *ptm, Set *pids);

/** Delete this group by migrating all transitive children to the parent. */
int ptg_delete(PTGroup *grp);

/** Is this group empty of processes directly belonging to it? */
bool ptg_is_empty(PTGroup *grp);

/** Is this group empty of processes directly or indirectly belonging to it? */
bool ptg_is_empty_recursive(PTGroup *grp);

/**
 * Kill all members of a PTGroup.
 *
 * @param grp Which PTGroup to kill the members of.
 * @param sig Which signal to send.
 * @param sigcont Whether to send SIGCONT to each PID after it's been sent \p sig.
 * @param ignore_self Whether to avoid sending the signal to this process (i.e. the manager itself)
 * @param ignore_set A set to which this routine will add each PID to this after
 *	that PID has been sent the signal, so as not to re-signal an already
 *	signaled PID. Optional. If passed with PIDs already in it, these will be
 *	excluded from being killed.
 */
int cg_kill(const char *unused, const PTGroup *grp, int sig, bool sigcont, bool ignore_self,
    Set *ignore_set);

/**
 * As cg_kill, but then also carries out the same for each subgroup.
 *
 * @param rem Whether to delete this PTGroup after killing its members.
 */
int cg_kill_recursive(const char *unused, const PTGroup *grp, int sig, bool sigcont,
    bool ignore_self, bool rem, Set *ignore_set);

/**
 * Migrate the processes of this group to another group.
 *
 * Only the processes are moved; any sub-groups are not.
 */
int ptg_migrate(PTGroup *from, PTGroup *to);

/**
 * Migrate the transitive set of processes of this group to another group. If
 * \p rem is set, recursively delete the group afterwards.
 *
 * The sub-group hierarchy is collapsed by this operation.
 */
int ptg_migrate_recursive(PTGroup *from, PTGroup *to, bool rem);

/**
 * Serialise a PTGroup to JSON, storing name, full-name, ID, contained PIDs, and
 * subgroups in full.
 *
 * @returns 0 and sets \p out to the cJSON object if successful.
 * @returns -errno on failure.
 */
int ptg_to_json(PTGroup *grp, cJSON **out);

/**
 * Create a new PTManager with the given Manager and name, which will form the
 * root name of its hierarchy of PTGroups.
 *
 * The PTManager object takes ownership of \p name.
 *
 * @returns 0 if allocation fails.
 */
PTManager *ptmanager_new(Manager *manager, char *name);

/**
 * Create a new PTManager with the given Manager by deserialising from the given
 * JSON object.
 *
 * @returns 0 if allocation fails.
 */
PTManager *ptmanager_new_from_json(Manager *manager, cJSON *obj);

/** Find a PTGroup by its full name. */
PTGroup *ptmanager_find_ptg_by_full_name(PTManager *ptm, const char *id);

/** Notify a PTManager of a fork event. @returns -errno on failure. */
int ptmanager_fork(PTManager *ptm, pid_t ppid, pid_t pid);

/** Notify a PTManager of an exit event. @returns -errno on failure. */
int ptmanager_exit(PTManager *ptm, pid_t pid);

/**
 * Serialise PTGroups state to a cJSON object. Sets \p out to the output cJSON
 * object.
 *
 * @returns 0 on success.
 * @returns -errno on failure.
 */
int ptmanager_to_json(PTManager *ptm, cJSON **out);

/** Find the unit corresponding to a given PID. */
Unit *manager_get_unit_by_pid(Manager *m, pid_t pid);

/** Create the PTGroup for a unit, if it doesn't yet exist. */
int unit_realize_ptgroup(Unit *u);

#endif /* PTGROUP_H_ */
