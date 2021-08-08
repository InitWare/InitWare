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
 * JournalD stream protocol (/run/systemd/journal/stdout) reader.
 */

#ifndef INP_JDSTREAM_H_
#define INP_JDSTREAM_H_

#include "bsdqueue.h"
#include "ev.h"

struct Evlogd;

struct JDStream {
	struct Evlogd *manager;
	ev_io watch;

	TAILQ_HEAD(clients, JDStreamClient) clients;
};

typedef struct JDStream JDStream;

/**
 * Initialise JournalD stream protocol support.
 *
 * @param fd An existing FD to use, or -1. If -1, then a new socket is bound.
 */
int jdstream_init(struct Evlogd *manager, JDStream *jds, int fd);

#endif /* JD_STREAM_H_ */
