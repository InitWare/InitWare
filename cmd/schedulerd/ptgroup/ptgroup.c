/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */

/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

#include "ptgroup.h"
#include "cjson-util.h"
#include "special.h"
#include "strv.h"
#include "unit.h"

static char **
_ptgroup_full_name(PTGroup *grp)
{
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

static char *
ptgroup_full_name(PTGroup *grp)
{
	char **strv = _ptgroup_full_name(grp);
	char *joint;
	if (!strv)
		return NULL;
	joint = strv_join(strv, "");
	strv_free(strv);
	return joint;
}

/*
 * Initialise the fields of a ptgroup - frees everything but the structure
 * itself on failure. Sets manager to parent->manager if parent is set.
 */
static int
ptgroup_init(PTGroup *grp, PTGroup *parent, const char *name)
{
	grp->name = strdup(name);
	if (!grp->name)
		goto fail;
	if (parent)
		grp->manager = parent->manager;
	grp->parent = parent;
	grp->full_name = ptgroup_full_name(grp);
	if (!grp->full_name)
		goto fail;
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

static int
ptgroup_init_from_json(PTGroup *grp, PTGroup *parent, cJSON *obj)
{
	cJSON *oCld;
	cJSON *oProc;

	grp->name = xcJSON_steal_valuestring(cJSON_GetObjectItem(obj, "name"));
	if (parent)
		grp->manager = parent->manager;
	grp->parent = parent;
	grp->full_name = xcJSON_steal_valuestring(
		cJSON_GetObjectItem(obj, "full_name"));

	grp->groups = set_new(trivial_hash_func, trivial_compare_func);
	if (!grp->groups)
		goto fail;

	grp->processes = set_new(trivial_hash_func, trivial_compare_func);
	if (!grp->processes)
		goto fail;

	cJSON_ArrayForEach(oCld, cJSON_GetObjectItem(obj, "groups"))
	{
		PTGroup *subgrp = malloc0(sizeof *subgrp);

		if (!subgrp)
			goto fail;

		if (ptgroup_init_from_json(subgrp, grp, oCld) < 0)
			goto fail;

		if (set_put(grp->groups, subgrp) < 0)
			goto fail;
	}

	cJSON_ArrayForEach(oProc, cJSON_GetObjectItem(obj, "processes"))
	{
		pid_t pid = cJSON_GetNumberValue(oProc);

		assert(oProc > 0);

		if (set_put(grp->processes, PID_TO_PTR(pid)) < 0)
			goto fail;
	}

	return 0;

fail:
	/* FIXME: properly recursive deletion */
	free(grp->name);
	free(grp->full_name);
	set_free(grp->groups);
	set_free(grp->processes);
	return -ENOMEM;
}

static void
ptgroup_free(PTGroup *grp)
{
	free(grp->name);
	free(grp->full_name);
	set_free(grp->groups);
	set_free(grp->processes);
	free(grp);
}

static int
manager_notify_ptgroup_empty(Manager *m, PTGroup *grp)
{
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

static int
ptgroup_exit(PTManager *ptm, PTGroup *grp, pid_t pid)
{
	int r;
	PTGroup *cld;
	void *pp;
	Iterator i;

	SET_FOREACH (pp, grp->processes, i)
		if (PTR_TO_PID(pp) == pid) {
			if (!set_remove(grp->processes, pp))
				log_error(
					"ptgroup %s: failed to remove PID %lu\n",
					grp->full_name, (unsigned long)pid);
			log_debug("ptgroup %s: removed PID %lu\n",
				grp->full_name, (unsigned long)pid);
			if (ptg_is_empty_recursive(grp))
				manager_notify_ptgroup_empty(grp->manager, grp);
			return 1;
		}

	SET_FOREACH (cld, grp->groups, i) {
		r = ptgroup_exit(ptm, cld, pid);
		if (r != 0) {
			if (ptg_is_empty_recursive(grp))
				manager_notify_ptgroup_empty(grp->manager, grp);
			return r;
		}
	}

	return 0;
}

static int
ptgroup_fork(PTGroup *grp, pid_t ppid, pid_t pid)
{
	int r;
	PTGroup *cld;
	void *pp;
	Iterator i;

	SET_FOREACH (pp, grp->processes, i)
		if (PTR_TO_PID(pp) == ppid) {
			r = set_put(grp->processes, PID_TO_PTR(pid));
			if (!r)
				log_error(
					"ptgroup %s: failed to add PID %lu: %s\n",
					grp->full_name, (unsigned long)pid,
					strerror(-r));
			else
				log_debug("ptgroup %s: added PID %lu\n",
					grp->full_name, (unsigned long)pid);
			return 1;
		}

	SET_FOREACH (cld, grp->groups, i) {
		r = ptgroup_fork(cld, ppid, pid);
		if (r != 0)
			return r;
	}

	return 0;
}

static PTGroup *
ptgroup_find_by_full_name(PTGroup *grp, const char *id)
{
	PTGroup *r;
	PTGroup *cld;
	Iterator i;

	if (streq(grp->full_name, id))
		return grp;

	SET_FOREACH (cld, grp->groups, i) {
		r = ptgroup_find_by_full_name(cld, id);
		if (r != NULL)
			return r;
	}

	return NULL;
}

static PTGroup *
ptgroup_find_by_pid(PTGroup *grp, pid_t pid)
{
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
int
_ptgroup_move_or_add(PTGroup *grp, PTManager *ptm, pid_t pid)
{
	int r;
	PTGroup *prev = ptgroup_find_by_pid(&ptm->group, pid);

	if (prev && prev == grp)
		return 0; /* already have it in the desired group */
	else if (prev) {
		if (!set_remove(prev->processes, PID_TO_PTR(pid)))
			log_error(
				"ptgroup %s: failed to remove PID %lu from group\n",
				prev->full_name, (unsigned long)pid);
		else
			log_debug("ptgroup %s: removed PID %lu\n",
				prev->full_name, (unsigned long)pid);
	}

	log_debug("ptgroup %s: adding PID %lu\n", grp->full_name,
		(unsigned long)pid);
	r = set_put(grp->processes, PID_TO_PTR(pid));
	if (r < 0)
		return r;
	return prev ? 1 : 2;
}

/* JSONise into an empty object already created */
static int
ptgroup_to_json_into(PTGroup *grp, cJSON *oGrp)
{
	if (!cJSON_AddStringToObject(oGrp, "name", grp->name))
		return -ENOMEM;
	if (!cJSON_AddStringToObject(oGrp, "full_name", grp->full_name))
		return -ENOMEM;
	if (!set_isempty(grp->groups)) {
		cJSON *oGroups;
		PTGroup *cld;
		Iterator i;

		oGroups = cJSON_AddArrayToObject(oGrp, "groups");
		if (!oGroups)
			return -ENOMEM;

		SET_FOREACH (cld, grp->groups, i) {
			cJSON *oCld;
			int r;

			oCld = cJSON_CreateObject();
			if (!oCld)
				return -ENOMEM;

			if (!cJSON_AddItemToArray(oGroups, oCld)) {
				cJSON_Delete(oCld);
				return -ENOMEM;
			}

			r = ptgroup_to_json_into(cld, oCld);
			if (r < 0)
				return r;
		}
	}
	if (!set_isempty(grp->processes)) {
		Iterator i;
		cJSON *oProcs;
		void *pp;

		oProcs = cJSON_AddArrayToObject(oGrp, "processes");
		if (!oProcs)
			return -ENOMEM;

		SET_FOREACH (pp, grp->processes, i) {
			cJSON *oProc;

			oProc = cJSON_CreateNumber(PTR_TO_PID(pp));
			if (!oProc)
				return -ENOMEM;
			if (!cJSON_AddItemToArray(oProcs, oProc))
				return -ENOMEM;
		}
	}

	return 0;
}

/**
 * PTGroup public interface
 */

PTGroup *
ptgroup_new(PTGroup *parent, char *name)
{
	PTGroup *cld;
	Iterator i;
	PTGroup *grp;

	SET_FOREACH (cld, parent->processes, i) {
		if (streq(cld->name, name)) {
			log_debug("Returning existing PTGroup %s\n",
				cld->full_name);
			return cld;
		}
	}

	grp = malloc0(sizeof(PTGroup));
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

int
ptgroup_attach_many(PTGroup *grp, PTManager *ptm, Set *pids)
{
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

void
ptg_release(PTGroup *grp)
{
	PTGroup *cld;
	Iterator i;
	Unit *u;

	assert(grp);

	if (!ptg_is_empty_recursive(grp))
		log_debug(
			"ptgroup %s: releasing when non-empty; processes will be lost\n",
			grp->full_name);

	SET_FOREACH (cld, grp->groups, i)
		ptg_release(cld);

	if (grp->parent)
		set_remove(grp->parent->groups, grp);
	u = hashmap_remove(grp->manager->ptgroup_unit, grp);

	if (u) {
		u->ptgroup = NULL;
		u->cgroup_realized = 0;
	}

	log_debug("ptgroup %s: released\n", grp->full_name);
	ptgroup_free(grp);
}

bool
ptg_is_empty(PTGroup *grp)
{
	assert(grp);
	return set_isempty(grp->processes);
}

bool
ptg_is_empty_recursive(PTGroup *grp)
{
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

/**
 * Recursively kill processes of a PTGroup.
 *
 * @returns 1 if some processes were killed.
 * @returns 0 if there are no processes left to kill
 * @returns -errno if there was an error.
 */
int
cg_kill(const char *unused, const PTGroup *grp, int sig, bool sigcont,
	bool ignore_self, Set *s)
{
	_cleanup_set_free_ Set *allocated_set = NULL;
	bool done = false;
	int r, ret = 0;
	pid_t my_pid;

	assert(sig >= 0);

	if (!s) {
		s = allocated_set = set_new(trivial_hash_func,
			trivial_compare_func);
		if (!s)
			return -ENOMEM;
	}

	my_pid = getpid();

	do {
		void *pp;
		pid_t pid = 0;
		Iterator i;
		done = true;

		SET_FOREACH (pp, grp->processes, i) {
			pid = PTR_TO_PID(pp);

			if (ignore_self && pid == my_pid)
				continue;

			if (set_get(s, LONG_TO_PTR(pid)) == LONG_TO_PTR(pid))
				continue;

			if (kill(pid, sig) < 0) {
				if (ret >= 0 && errno != ESRCH)
					ret = -errno;
			} else if (ret == 0) {
				if (sigcont)
					kill(pid, SIGCONT);

				ret = 1;
			}

			done = false;

			r = set_put(s, LONG_TO_PTR(pid));
			if (r < 0) {
				if (ret >= 0)
					return r;

				return ret;
			}
		}

		if (r < 0) {
			if (ret >= 0)
				return r;

			return ret;
		}

		/*
		 * todo: race to delete any newly-forked processes?
		 */

	} while (!done);

	return ret;
}

int
cg_kill_recursive(const char *unused1, const PTGroup *grp, int sig,
	bool sigcont, bool ignore_self, bool rem, Set *s)
{
	PTGroup *cld;
	_cleanup_set_free_ Set *allocated_set = NULL;
	int r, ret = 0;
	char *fn;
	Iterator i;

	assert(grp);
	assert(sig >= 0);

	if (!s) {
		s = allocated_set = set_new(trivial_hash_func,
			trivial_compare_func);
		if (!s)
			return -ENOMEM;
	}

	ret = cg_kill(unused1, grp, sig, sigcont, ignore_self, s);

	SET_FOREACH (cld, grp->groups, i) {
		r = cg_kill_recursive(unused1, cld, sig, sigcont, ignore_self,
			rem, s);
		if (ret >= 0 && r != 0)
			ret = r;
	}

	if (ret >= 0 && r < 0)
		ret = r;

	if (rem)
		/* TODO: delete group? */
		;

	return ret;
}

int
ptg_migrate(PTGroup *from, PTGroup *to)
{
	int r = set_merge(to->processes, from->processes);
	if (r < 0)
		goto fail;

fail:
	log_error("ptgroup %s: failed to migrate subprocesses to %s\n",
		from->full_name, to->full_name);
	return r;
}

int
ptg_migrate_recursive(PTGroup *from, PTGroup *to, bool rem)
{
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
			/* TODO: is it legal to modify while iterating a set? */
			set_remove(from->groups, cld);
	}

	if (rem)
		ptgroup_free(from);

	return 0;
}

int
ptg_to_json(PTGroup *grp, cJSON **out)
{
	cJSON *obj;
	int r;

	obj = cJSON_CreateObject();
	if (!obj)
		return -ENOMEM;

	r = ptgroup_to_json_into(grp, obj);
	if (r < 0)
		return r;

	*out = obj;

	return 0;
}

/**
 * PTManager methods
 */

PTManager *
ptmanager_new(Manager *manager, char *name)
{
	PTManager *ptm = malloc0(sizeof(PTManager));
	if (!ptm)
		return NULL;
	ptm->group.manager = manager;
	if (ptgroup_init(&ptm->group, NULL, name) < 0) {
		free(ptm);
		return NULL;
	}
	return ptm;
}

PTManager *
ptmanager_new_from_json(Manager *manager, cJSON *obj)
{
	PTManager *ptm = malloc0(sizeof(PTManager));
	if (!ptm)
		return NULL;
	ptm->group.manager = manager;

	if (ptgroup_init_from_json(&ptm->group, NULL, obj) < 0) {
		free(ptm);
		return NULL;
	}

	return ptm;
}

PTGroup *
ptmanager_find_ptg_by_full_name(PTManager *ptm, const char *id)
{
	return ptgroup_find_by_full_name(&ptm->group, id);
}

/** Notify a PTManager of an exit event. @returns -errno on failure. */
int
ptmanager_exit(PTManager *ptm, pid_t pid)
{
	int r = ptgroup_exit(ptm, &ptm->group, pid);
	if (!r)
		log_debug(
			"ptgroup: exited PID %lu was not in any of our groups",
			(unsigned long)pid);
	if (!hashmap_contains(ptm->group.manager->watch_pids1,
		    PID_TO_PTR(pid)) &&
		!hashmap_contains(ptm->group.manager->watch_pids2,
			PID_TO_PTR(pid)))
		log_debug(
			"ptgroup: xxx should probably not delete in this case!"); /* TODO: ! */
	/* TODO: Should we generate a SIGCHLD event if the process is not a
	 * direct child of ours? */
	return r;
}

int
ptmanager_fork(PTManager *ptm, pid_t ppid, pid_t pid)
{
	int r;

	if (ptgroup_find_by_pid(&ptm->group, pid)) {
		log_warning("ptgroup: already tracking PID %lu\n",
			(unsigned long)pid);
		return 0;
	}

	r = ptgroup_fork(&ptm->group, ppid, pid);
	if (!r)
		log_debug(
			"ptgroup: newly forked PID %lu's parent %lu was not in any of our groups",
			(unsigned long)ppid, (unsigned long)pid);
	return r;
}

int
ptmanager_to_json(PTManager *ptm, cJSON **out)
{
	return ptg_to_json(&ptm->group, out);
}

/**
 * Manager additional methods
 */

Unit *
manager_get_unit_by_pid(Manager *m, pid_t pid)
{
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

PTGroup *
unit_default_parent_ptgroup(Unit *u)
{
	int r;

	assert(u);

	if (UNIT_ISSET(u->slice)) {
		return UNIT_DEREF(u->slice)->ptgroup;
	} else
		return &u->manager->pt_manager->group;
}

static int
unit_create_ptgroups(Unit *u)
{
	PTGroup *grp;
	int r;
	bool was_in_hash = false;

	assert(u);

	grp = ptgroup_new(unit_default_parent_ptgroup(u), u->id);
	if (!grp) {
		log_error(
			"Failed to create ptgroup for unit %s: Out of memory.",
			u->id);
		return -ENOMEM;
	}

	r = hashmap_put(u->manager->ptgroup_unit, grp, u);

	if (r < 0) {
		log_error("Failed to add PTGroup hashmap entry for unit %s: %s",
			u->id, strerror(-r));
		return r;
	}

	if (u->ptgroup) {
		/* FIXME:  move any existing cgroup */
		log_error("PTGroup already exists for unit %s\n", u->id);
		abort();
		return -EEXIST;
	}

	u->ptgroup = grp;

	u->cgroup_realized = true;

	return 0;
}

int
unit_realize_ptgroup(Unit *u)
{
	assert(u);

	if (u->cgroup_realized)
		return 0;

	/* realise the parent slice PTGroup */
	if (UNIT_ISSET(u->slice))
		unit_realize_ptgroup(UNIT_DEREF(u->slice));

	/* now realise the unit's actual PTGroup */
	return unit_create_ptgroups(u);
}