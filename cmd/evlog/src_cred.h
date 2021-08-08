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

#ifndef INP_CRED_H_
#define INP_CRED_H_

#include <sys/types.h>

#include "socket-util.h"

struct SourceMetadata {
	char *systemd_slice;
	char *systemd_unit;
	char *systemd_user_unit;
	char *systemd_user_slice;
	char *systemd_session;
	uid_t systemd_user_uid;

	struct socket_ucred cred;
	char *command;
	char *exe;
	char *cmdline;
};

typedef struct SourceMetadata SourceMetadata;

int sourcemetadata_update_from_pid(SourceMetadata *metadata);

#endif /* INP_CRED_H_ */
