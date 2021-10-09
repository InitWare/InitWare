#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

${1:?} -E -dM -include linux/capability.h - </dev/null | \
	awk '/^#define[ \t]+CAP_[A-Z_]+[ \t]+/ { print $2; }' | \
	grep -v CAP_LAST_CAP