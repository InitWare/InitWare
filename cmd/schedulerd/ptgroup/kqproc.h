/* SPDX-License-Identifier: BSD-4-Clause OR LGPL-2.1-or-later */

/*
 * Copyright 2021 David Mackay. All rights reserved.
 */

/*
 * PTGroups using Kernel Queues with the PROC filter.
 */

#ifndef KQPROC_H_
#define KQPROC_H_

#include "ptgroup.h"

typedef struct Manager Manager;

/*
 * Setup KQueue-based process tracking, optionally reusing an existing KQ FD.
 *
 * @param with_fd Existing KQueue FD to use, or -1 to create a new FD.
 */
int manager_setup_kqproc_watch(Manager *m, int with_fd);

#endif /* KQPROC_H_ */
