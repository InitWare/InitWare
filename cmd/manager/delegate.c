
/*
 *	LICENCE NOTICE
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 *
 *	Copyright Notice
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */

#include "delegate.h"
#include "dbus-delegate.h"

/* clang-format off */
static const UnitActiveState state_translation_table[_DELEGATE_STATE_MAX] = {
	[DEVICE_DEAD] = UNIT_INACTIVE,
	[DELEGATE_OFFLINE] = UNIT_INACTIVE, 
	[DELEGATE_ONLINE] = UNIT_ACTIVE
};
/* clang-format on */

static void delegate_init(Unit *u)
{
	Delegate *self = DELEGATE(u);

	assert(self);
	assert(UNIT(self)->load_state == UNIT_STUB);

	UNIT(self)->job_timeout = u->manager->default_timeout_start_usec;

	UNIT(self)->ignore_on_isolate = true;
	UNIT(self)->ignore_on_snapshot = true;
}

static void delegate_done(Unit *u)
{
}

static void delegate_set_state(Delegate *self, DelegateState state)
{
	DelegateState old_state;
	assert(self);

	old_state = self->state;
	self->state = state;

	if (state != old_state)
		log_debug_unit(UNIT(self)->id, "%s changed %s -> %s", UNIT(self)->id,
		    delegate_state_to_string(old_state), delegate_state_to_string(state));

	unit_notify(UNIT(self), state_translation_table[old_state], state_translation_table[state],
	    true);
}

static int delegate_coldplug(Unit *u)
{
	Delegate *self = DELEGATE(u);
	int r;

	assert(self);
	assert(self->state == DELEGATE_DEAD);

	if (self->deserialized_state != self->state) {

		if (self->deserialized_state == DELEGATE_ONLINE) {
		}

		delegate_set_state(self, self->deserialized_state);
	}

	return 0;
}

static void delegate_dump(Unit *u, FILE *f, const char *prefix)
{
	Delegate *d = DELEGATE(u);

	assert(d);

	fprintf(f, "%sDelegate State: %s\n", prefix, delegate_state_to_string(d->state));
}

static UnitActiveState delegate_active_state(Unit *u)
{
	assert(u);

	return state_translation_table[DELEGATE(u)->state];
}

static const char *delegate_sub_state_to_string(Unit *u)
{
	assert(u);

	return delegate_state_to_string(DELEGATE(u)->state);
}

static void delegate_shutdown(Manager *m)
{
	assert(m);
}

static const char *const delegate_state_table[_DELEGATE_STATE_MAX] = {
	[DELEGATE_DEAD] = "dead",
	[DELEGATE_OFFLINE] = "offline",
	[DELEGATE_ONLINE] = "online",
};

DEFINE_STRING_TABLE_LOOKUP(delegate_state, DelegateState);

const UnitVTable delegate_vtable = {
        .object_size = sizeof(Delegate),
        .sections =
                "Unit\0"
                "Delegate\0"
                "Install\0",

        .no_instances = true,

        .init = delegate_init,

        .load = unit_load_fragment_and_dropin_optional,
        .done = delegate_done,
        .coldplug = delegate_coldplug,

        .dump = delegate_dump,

        .active_state = delegate_active_state,
        .sub_state_to_string = delegate_sub_state_to_string,

        .bus_interface = SCHEDULER_DBUS_INTERFACE ".Delegate",
        .bus_message_handler = bus_delegate_message_handler,
        .bus_invalidating_properties =  bus_delegate_invalidating_properties,

        .shutdown = delegate_shutdown,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Awaiting delegate %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Delegate %s online.",
                        [JOB_TIMEOUT]    = "Timed out waiting for delegate %s.",
                },
        },
};
