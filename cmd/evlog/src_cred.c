/*
 *    LICENCE NOTICE
 *
 * This source code is part of the InitWare Suite of Middleware, and it is
 * protected under copyright law. It may not be distributed, copied, or used,
 * except under the terms of the Library General Public Licence version 2.1 or
 * later, which should have been included in the file "LICENSE.md".
 *
 *    (c) 2021 David Mackay
 *        All rights reserved.
 */


#include "src_cred.h"
#include "util.h"

static inline void *take_ptr(void **ptr)
{
	void *res = *ptr;
	*ptr = NULL;
	return res;
}

#define TAKE_PTR(ptr) (typeof(ptr)) take_ptr((void **) &ptr)

int sourcemetadata_update_from_pid(SourceMetadata *metadata)
{
	int r;
	char *cmdline = NULL, *command = NULL, *exe = NULL;

#define CHECK(var)                                                          \
	if (r < 0) {                                                        \
		log_info_errno(-r, "Failed to get process metadata: %m\n"); \
		free(var);                                                  \
		var = NULL;                                                 \
	}

	log_debug("Updating metadata for PID %d\n", metadata->cred.pid);

	r = get_process_comm(metadata->cred.pid, &command);
	CHECK(command);
	r = get_process_cmdline(metadata->cred.pid, 0, true, &cmdline);
	CHECK(cmdline);
	r = get_process_exe(metadata->cred.pid, &exe);
	CHECK(exe);

#define REPLACE_IF_NONNULL(var)                \
	if (var) {                             \
		free(metadata->var);           \
		metadata->var = TAKE_PTR(var); \
	}
	REPLACE_IF_NONNULL(cmdline);
	REPLACE_IF_NONNULL(command);
	REPLACE_IF_NONNULL(exe);

	return 0;

fail:
	free(cmdline);
	free(command);
	free(exe);
	return r;
}