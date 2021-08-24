#ifndef BSDSOCKET_H_
#define BSDSOCKET_H_

#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#warning No MSG_NOSIGNAL.
#define MSG_NOSIGNAL 0
#endif

#endif /* BSDSOCKET_H_ */
