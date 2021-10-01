#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct Transaction Transaction;

#include "hashmap.h"
#include "job.h"
#include "manager.h"
#include "unit.h"

struct Transaction {
	/* Jobs to be added */
	Hashmap *jobs; /* Unit object => Job object list 1:1 */
	Job *anchor_job; /* the job the user asked for */
	bool irreversible;
};

/* Describes a job being submitted for inclusion in a transaction. */
struct tx_job_submission {
	Unit *unit;	/* unit on which to operate */
	JobType type;	/* kind of job */
	Job *parent;	/* parent job which this was pulled-in by */
	bool matters;	/* whether this job is essential to the parent job */
	bool override;	/* whether to override any existing jobs for the unit */
	bool conflicts; /* whether the job was brought in by a Conflicts= dep */
	bool ignore_requirements; /* whether to skip adding requirement deps */
	bool ignore_order; /* whether to ignore ordering requirements when running job */
};

Transaction *transaction_new(bool irreversible);
void transaction_free(Transaction *tr);

/**
 * Submit a job to the transaction. Dependency jobs are added if appropriate.
 */
int tx_submit_job(Transaction *, struct tx_job_submission *, sd_bus_error *);

int transaction_activate(Transaction *tr, Manager *m, JobMode mode,
	sd_bus_error *e);
int transaction_add_isolate_jobs(Transaction *tr, Manager *m);
void transaction_abort(Transaction *tr);
