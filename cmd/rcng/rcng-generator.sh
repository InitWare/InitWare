#######################################################################
#
#       LICENCE NOTICE
#
# These coded instructions, statements, and computer programs are part
# of the  InitWare Suite of Middleware,  and  they are protected under
# copyright law. They may not be distributed,  copied,  or used except
# under the provisions of  the  terms  of  the  Library General Public
# Licence version 2.1 or later, in the file "LICENSE.md", which should
# have been included with this software
#
#       Copyright Notice
#
#   (c) 2021 David Mackay
#       All rights reserved.
#
#######################################################################
#
# InitWare generator for conversion of RC-NG scripts to InitWare unitfiles.
#

late_divider=/etc/rc.d/FILESYSTEMS

export HOME=/
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
umask 022

autoboot=yes
rc_fast=yes	# run_rc_command(): do fast booting

#
# Completely ignore INT and QUIT at the outer level.  The rc_real_work()
# function should do something different.
#
trap '' INT QUIT

RC_PID=$$

#
# Get a list of all rc.d scripts, and use rcorder to choose
# what order to execute them.
#
# For testing, allow RC_FILES_OVERRIDE from the environment to
# override this.
#
scripts=$(for rcd in ${rc_directories:-/etc/rc.d /usr/local/etc/rc.d}; do
	test -d ${rcd} && echo ${rcd}/*;
done)
files=$(rcorder -s nostart ${rc_rcorder_flags} ${scripts})

if [ -n "${RC_FILES_OVERRIDE}" ]; then
	files="${RC_FILES_OVERRIDE}"
fi

for _rc_elem in $files ; do
	if [ -z $_past_divider ] ; then
		[ $_rc_elem = $late_divider ] &&  _past_divider=1
		basename=$(basename $_rc_elem)
		# fake up a unitfile for the early services which we don't want
		# the manager to interfere with, so as to satisfy dependencies.
		cat > $3/$basename.service <<EOF
[Unit]
Description=Early Mewburn RC script $basename

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
EOF
	else
		default=no
		$_rc_elem enabled > /dev/null 2>&1 && default=yes
		/usr/local/libexec/InitWare/rcng2unit $_rc_elem $3 $default
	fi
done
