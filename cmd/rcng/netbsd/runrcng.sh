#!/bin/sh

export HOME=/
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
umask 022

. /etc/rc.subr
. /etc/rc.conf
_rc_conf_loaded=true

# rc.subr redefines echo and printf.  Undo that here.
unset echo ; unalias echo
unset printf ; unalias printf

if ! checkyesno rc_configured; then
	echo "/etc/rc.conf is not configured.  Multiuser boot aborted."
	exit 1
fi

autoboot=yes

RC_PID=$$

run_rc_script $@
