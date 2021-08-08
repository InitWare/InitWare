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
/**
 * The InitWare Event Log daemon.
 */

#ifndef EVLOGD_H_
#define EVLOGD_H_

#include "backend.h"
#include "ev.h"
#include "jd_stream.h"

#define DATABASE AbsDir_PkgRunState "/evlog/evlog.db"

#define JD_STREAM_SOCKET AbsDir_PkgRunState "/evlog/stdout"

struct Evlogd {
	/* The event loop; we just make this ev_default_loop. */
	struct ev_loop *evloop;

	ev_signal sigint, sigterm;

	Backend backend;
	/* Journald stream interface. */
	JDStream jdstream;
};

typedef struct Evlogd Evlogd;

#endif /* EVLOGD_H_ */
