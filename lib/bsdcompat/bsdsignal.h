#ifndef BSDSIGNAL_H_
#define BSDSIGNAL_H_

#include <sys/signal.h>

#ifndef _NSIG
#ifdef SIGRTMAX
#define _NSIG SIGRTMAX + 1
#else
#define _NSIG NSIG
#endif /* SIGRTMAX */
#endif /* _NSIG */

#endif /* BSDSIGNAL_H_ */
