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

#ifndef DELEGATE_H_
#define DELEGATE_H_

typedef struct Delegate Delegate;

#include "unit.h"

typedef enum DelegateState {
	DELEGATE_DEAD,
	DELEGATE_OFFLINE,
	DELEGATE_ONLINE,
	_DELEGATE_STATE_MAX,
	_DELEGATE_STATE_INVALID = -1
} DelegateState;


struct Delegate {
	Unit meta;

	Unit *restarter;

	DelegateState state, deserialized_state;
};

extern const UnitVTable delegate_vtable;

const char *delegate_state_to_string(DelegateState i) _const_;
DelegateState delegate_state_from_string(const char *s) _pure_;

#endif /* DELEGATE_H_ */
