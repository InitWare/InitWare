#ifndef BSDUCRED_H_
#define BSDUCRED_H_

#include "svc-config.h"

#ifndef HAVE_socket_struct_ucred
/**
 * A replica of Linux's struct ucred (an entirely inappropriate name).
 * This is reasonable conjunction of the socket peer/sender credentials we
 * expect all supported platforms to offer us.
 */
struct socket_ucred {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};
#else
#define socket_ucred ucred
#endif

#endif /* BSDUCRED_H_ */
