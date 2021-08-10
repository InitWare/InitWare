#!/bin/sh
#
# PROVIDE: initware
# REQUIRE: dbus
#

. /etc/rc.subr

name="initware"
rcvar=$name
pidfile="@VARBASE@/run/InitWare/initware.pid"
command="@PREFIX@/libexec/InitWare/svc.managerd"
command_args="--system --daemonise"
start_precmd="initware_prestart"
stop_cmd="initware_stop"

initware_prestart() {
	@PREFIX@/libexec/InitWare/tmpfiles --create
}

initware_stop() {
	@PREFIX@/bin/svcctl halt
	pkill evlogd
}

load_rc_config $name
run_rc_command "$1"
