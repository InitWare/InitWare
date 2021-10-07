/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright: systemd authors
 */

#include "fdset.h"
#include "sd-daemon.h"
#include "util.h"

int
fdset_new_listen_fds(FDSet **_s, bool unset)
{
	int n, fd, r;
	FDSet *s;

	assert(_s);

	/* Creates an fdset and fills in all passed file descriptors */

	s = fdset_new();
	if (!s) {
		r = -ENOMEM;
		goto fail;
	}

	n = sd_listen_fds(unset);
	for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
		r = fdset_put(s, fd);
		if (r < 0)
			goto fail;
	}

	*_s = s;
	return 0;

fail:
	if (s)
		set_free(MAKE_SET(s));

	return r;
}