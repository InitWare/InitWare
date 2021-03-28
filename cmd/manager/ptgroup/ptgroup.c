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

#include "ptgroup.h"
#include "special.h"
#include "strv.h"
#include "unit.h"

static char **_ptgroup_full_name(PTGroup *grp) {
        if (grp->parent) {
                char **inter = _ptgroup_full_name(grp->parent);
                if (!inter)
                        return NULL;
                if (strv_extend(&inter, "/") < 0) {
                        strv_free(inter);
                        return NULL;
                }
                if (strv_extend(&inter, grp->name) < 0) {
                        strv_free(inter);
                        return NULL;
                }
                return inter;
        }
        return strv_new(grp->name, NULL);
}

static char *ptgroup_full_name(PTGroup *grp) {
        char **strv = _ptgroup_full_name(grp);
        char *joint;
        if (!strv)
                return NULL;
        joint = strv_join(strv, "");
        strv_free(strv);
        return joint;
}

/*
 * initialise the fields of a ptgroup - frees everything but the structure
 * itself on failure
 */
static int ptgroup_init(PTGroup *grp, PTGroup *parent, char *name) {
        grp->name = name;
        grp->parent = parent;
        grp->full_name = ptgroup_full_name(grp);
        if (!grp->full_name)
                goto fail;
        grp->id = rand();
        grp->groups = set_new(trivial_hash_func, trivial_compare_func);
        if (!grp->groups)
                goto fail;
        grp->processes = set_new(trivial_hash_func, trivial_compare_func);
        if (!grp->processes)
                goto fail;

        return 0;

fail:
        free(grp->name);
        free(grp->full_name);
        set_free(grp->groups);
        set_free(grp->processes);
        return -1;
}

static void ptgroup_free(PTGroup *grp) {
        free(grp->name);
        free(grp->full_name);
        set_free(grp->groups);
        set_free(grp->processes);
        free(grp);
}

static int manager_notify_ptgroup_empty(Manager *m, PTGroup *grp) {
        Unit *u;
        int r;

        assert(m);
        assert(grp);

        log_debug("ptgroup %s is empty\n", grp->full_name);

        u = hashmap_get(m->ptgroup_unit, grp);
        if (u) {
                r = ptg_is_empty_recursive(u->ptgroup);
                if (r > 0) {
                        if (UNIT_VTABLE(u)->notify_cgroup_empty)
                                UNIT_VTABLE(u)->notify_cgroup_empty(u);

                        unit_add_to_gc_queue(u);
                }
        }

        return 0;
}

static int ptgroup_exit(PTManager *ptm, PTGroup *grp, pid_t pid) {
        int r;
        PTGroup *cld;
        void *pp;
        Iterator i;

        SET_FOREACH (pp, grp->processes, i)
                if (PTR_TO_PID(pp) == pid) {
                        if (!set_remove(grp->processes, pp))
                                log_error(
                                        "ptgroup %s: Failed to remove PID %lu\n",
                                        grp->full_name,
                                        (unsigned long) pid);
                        log_debug("ptgroup %s: removed PID %lu\n", grp->full_name, (unsigned long) pid);
                        if (ptg_is_empty_recursive(grp))
                                manager_notify_ptgroup_empty(ptm->manager, grp);
                        return 1;
                }

        SET_FOREACH (cld, grp->groups, i) {
                r = ptgroup_exit(ptm, cld, pid);
                if (r != 0) {
                        if (ptg_is_empty_recursive(grp))
                                manager_notify_ptgroup_empty(ptm->manager, grp);
                        return r;
                }
        }

        return 0;
}

static int ptgroup_fork(PTGroup *grp, pid_t ppid, pid_t pid) {
        int r;
        PTGroup *cld;
        void *pp;
        Iterator i;

        SET_FOREACH (pp, grp->processes, i)
                if (PTR_TO_PID(pp) == ppid) {
                        r = set_put(grp->processes, PID_TO_PTR(pid));
                        if (!r)
                                log_error(
                                        "ptgroup %s: Failed to add PID %lu: %s\n",
                                        grp->full_name,
                                        (unsigned long) pid,
                                        strerror(-r));
                        else
                                log_debug("ptgroup %s: added PID %lu\n", grp->full_name, (unsigned long) pid);
                        return 1;
                }

        SET_FOREACH (cld, grp->groups, i) {
                r = ptgroup_fork(cld, ppid, pid);
                if (r != 0)
                        return r;
        }

        return 0;
}

PTGroup *ptgroup_find_by_pid(PTGroup *grp, pid_t pid) {
        PTGroup *r;
        PTGroup *cld;
        void *pp;
        Iterator i;

        SET_FOREACH (pp, grp->processes, i)
                if (PTR_TO_PID(pp) == pid) {
                        return grp;
                }

        SET_FOREACH (cld, grp->groups, i) {
                r = ptgroup_find_by_pid(cld, pid);
                if (r != NULL)
                        return r;
        }

        return NULL;
}

/**
 * Try to add the given PID to grp, removing it from any group to which it was
 * previously added.
 *
 * First we check if the PID is already in another subgroup of the same manager.
 * If so, we either delete it from there if that's a different group to grp,
 * where we want to put the PID, or we just leave it if it's already in grp,
 * and return 0.
 *
 * Otherwise we add the PID to the given group, and we return 1 if we already
 * had the PID in another group, otherwise we return 2. If any errors occurred,
 * we return -errno.
 */
int _ptgroup_move_or_add(PTGroup *grp, PTManager *ptm, pid_t pid) {
        int r;
        PTGroup *prev = ptgroup_find_by_pid(&ptm->group, pid);

        if (prev && prev == grp)
                return 0; /* already have it in the desired group */
        else if (prev) {
                if (!set_remove(prev->processes, PID_TO_PTR(pid)))
                        log_error(
                                "ptgroup %s: failed to remove PID %lu from group\n",
                                prev->full_name,
                                (unsigned long) pid);
                else
                        log_debug("ptgroup %s: removed PID %lu\n", prev->full_name, (unsigned long) pid);
        }

        log_debug("ptgroup %s: Adding PID %lu\n", grp->full_name, (unsigned long) pid);
        r = set_put(grp->processes, PID_TO_PTR(pid));
        if (r < 0)
                return r;
        return prev ? 1 : 2;
}

/**
 * PTGroup public interface
 */

PTGroup *ptgroup_new(PTGroup *parent, char *name) {
        PTGroup *grp = malloc0(sizeof(PTGroup));
        if (!grp)
                return NULL;
        if (ptgroup_init(grp, parent, name) < 0) {
                free(grp);
                return NULL;
        }
        if (set_put(parent->groups, grp) < 0) {
                ptgroup_free(grp);
                return NULL;
        }

        log_debug("ptgroup: allocated new group %s\n", grp->full_name);
        return grp;
}

bool ptg_is_empty(PTGroup *grp) {
        assert(grp);
        return set_isempty(grp->processes);
}


bool ptg_is_empty_recursive(PTGroup *grp) {
        PTGroup *cld;
        Iterator i;
        assert(grp);

        if (!ptg_is_empty(grp))
                return false;

        SET_FOREACH (cld, grp->groups, i) {
                if (!ptg_is_empty_recursive(cld))
                        return false;
        }

        return true;
}

int ptg_migrate(PTGroup *from, PTGroup *to) {
        int r = set_merge(to->processes, from->processes);
        if (r < 0)
                goto fail;

fail:
        log_error("ptgroup %s: Failed to migrate subprocesses to %s\n", from->full_name, to->full_name);
        return r;
}

int ptg_migrate_recursive(PTGroup *from, PTGroup *to, bool rem) {
        int r;
        PTGroup *cld;
        Iterator it;

        r = ptg_migrate(from, to);
        if (r < 0)
                return r;

        SET_FOREACH (cld, from->groups, it) {
                r = ptg_migrate_recursive(cld, to, rem);
                if (r < 0)
                        return r;
                if (rem)
                        set_remove(from->groups, cld); /* TODO: is it legal to modify while iterating a set? */
        }

        if (rem)
                ptgroup_free(from);

        return 0;
}

/**
 * PTManager methods
 */

PTManager *ptmanager_new(Manager *manager, char *name) {
        PTManager *ptm = malloc0(sizeof(PTManager));
        if (!ptm)
                return NULL;
        ptm->manager = manager;
        if (ptgroup_init(&ptm->group, NULL, name) < 0) {
                free(ptm);
                return NULL;
        }
        return ptm;
}

int ptgroup_attach_many(PTGroup *grp, PTManager *ptm, Set *pids) {
        Iterator i;
        void *pp;
        int r = 0;

        SET_FOREACH (pp, pids, i) {
                int r2 = ptgroup_attach(grp, ptm, PTR_TO_PID(pp));
                if (r2 < 0)
                        r = r2;
        }

        return r;
}

int ptmanager_fork(PTManager *ptm, pid_t ppid, pid_t pid) {
        int r;

        if (ptgroup_find_by_pid(&ptm->group, pid)) {
                log_warning("Already tracking PID %lu\n", (unsigned long) pid);
                return 0;
        }

        r = ptgroup_fork(&ptm->group, ppid, pid);
        if (!r)
                log_warning(
                        "Newly forked PID %lu's parent %lu was not in any of our groups",
                        (unsigned long) ppid,
                        (unsigned long) pid);
        return r;
}

/** Notify a PTManager of an exit event. @returns -errno on failure. */
int ptmanager_exit(PTManager *ptm, pid_t pid) {
        int r = ptgroup_exit(ptm, &ptm->group, pid);
        if (!r)
                log_warning("Exited PID %lu was not in any of our groups", (unsigned long) pid);
        if (!hashmap_contains(ptm->manager->watch_pids1, PID_TO_PTR(pid)) &&
            !hashmap_contains(ptm->manager->watch_pids2, PID_TO_PTR(pid)))
                log_error("Should probably not delete in this case!"); /* TODO: ! */
        /* TODO: Should we generate a SIGCHLD event if the process is not a
         * direct child of ours? */
        return r;
}

/**
 * Manager additional methods
 */

Unit *manager_get_unit_by_pid(Manager *m, pid_t pid) {
        PTGroup *grp;

        assert(m);

        if (pid <= 1)
                return NULL;

        grp = ptgroup_find_by_pid(&m->pt_manager->group, pid);
        if (!grp)
                return NULL;

        return hashmap_get(m->ptgroup_unit, grp);
}


/**
 * Unit additional methods
 */

PTGroup *unit_default_parent_ptgroup(Unit *u) {
        int r;

        assert(u);

        if (UNIT_ISSET(u->slice)) {
                return UNIT_DEREF(u->slice)->ptgroup;
        } else
                return &u->manager->pt_manager->group;
}

static int unit_create_ptgroups(Unit *u) {
        PTGroup *grp;
        int r;
        bool was_in_hash = false;

        assert(u);

        grp = ptgroup_new(unit_default_parent_ptgroup(u), u->id);
        if (!grp) {
                log_error("Failed to create ptgroup for unit %s: Out of memory.", u->id);
                return -ENOMEM;
        }

        r = hashmap_put(u->manager->ptgroup_unit, grp, u);

        if (r < 0) {
                log_error("Failed to add PTGroup hashmap entry for unit %s: %s", u->id, strerror(-r));
                return r;
        }

        if (u->ptgroup) {
                /* TODO:  move any existing cgroup */
                log_error("PTGroup already exists for unit %s\n", u->id);
                abort();
                return -EEXIST;
        }

        u->ptgroup = grp;

        u->cgroup_realized = true;

        return 0;
}

int unit_realize_ptgroup(Unit *u) {
        assert(u);

        if (u->cgroup_realized)
                return 0;

        /* realise the parent slice PTGroup */
        if (UNIT_ISSET(u->slice))
                unit_realize_ptgroup(UNIT_DEREF(u->slice));

        /* now realise the unit's actual PTGroup */
        return unit_create_ptgroups(u);
}