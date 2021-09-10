#!/bin/bash
set -ex

systemd-analyze set-log-level debug

# Emulates systemd-run to overcome its limitations on RHEL-7, like nonexistent
# support for --wait and only a handful of supported properties.
systemd-run-wait() {
    local unit="$1"
    local unitfile=/etc/systemd/system/$unit

    shift

    cat > $unitfile <<EOF
[Service]
StandardOutput=tty
StandardError=tty
EOF

    # The $OPTIND variable used by geopts is NOT reset on function exit in the
    # same shell session, so let's do it manually to always get relevant results
    OPTIND=1

    while getopts p: opt ; do
        case $opt in
            p) echo "$OPTARG" >> $unitfile ;;
        esac
    done
    shift $((OPTIND - 1))
    echo "ExecStart=/usr/bin/env $@" >> $unitfile
    systemctl daemon-reload

    systemctl start $unit
    while systemctl is-active -q $unit ; do
        sleep 1
    done
    ! systemctl is-failed -q $unit
}

systemd-run-wait simple1.service -p Type=simple -p ExecStopPost='/bin/touch /run/simple1' true
test -f /run/simple1

! systemd-run-wait simple2.service -p Type=simple -p ExecStopPost='/bin/touch /run/simple2' false
test -f /run/simple2

cat > /tmp/forking1.sh <<EOF
#!/bin/bash

set -eux

sleep 4 &
MAINPID=\$!
disown

systemd-notify MAINPID=\$MAINPID
EOF
chmod +x /tmp/forking1.sh

# RHEL 7 doesn't support NotifyAccess=exec
systemd-run-wait forking1.service -p Type=forking -p NotifyAccess=main -p ExecStopPost='/bin/touch /run/forking1' /tmp/forking1.sh
test -f /run/forking1

cat > /tmp/forking2.sh <<EOF
#!/bin/bash

set -eux

( sleep 4; exit 1 ) &
MAINPID=\$!
disown

systemd-notify MAINPID=\$MAINPID
EOF
chmod +x /tmp/forking2.sh

# RHEL 7 doesn't support NotifyAccess=exec
! systemd-run-wait forking2.service -p Type=forking -p NotifyAccess=main -p ExecStopPost='/bin/touch /run/forking2' /tmp/forking2.sh
test -f /run/forking2

systemd-run-wait oneshot1.service -p Type=oneshot -p ExecStopPost='/bin/touch /run/oneshot1' true
test -f /run/oneshot1

! systemd-run-wait oneshot2.service -p Type=oneshot -p ExecStopPost='/bin/touch /run/oneshot2' false
test -f /run/oneshot2

systemd-run-wait dbus1.service -p Type=dbus -p BusName=systemd.test.ExecStopPost -p ExecStopPost='/bin/touch /run/dbus1' \
    busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su systemd.test.ExecStopPost 4 \
    || :
test -f /run/dbus1

! systemd-run-wait dbus2.service -p Type=dbus -p BusName=systemd.test.ExecStopPost -p ExecStopPost='/bin/touch /run/dbus2' true
test -f /run/dbus2

cat > /tmp/notify1.sh <<EOF
#!/bin/bash

set -eux

systemd-notify --ready
EOF
chmod +x /tmp/notify1.sh

systemd-run-wait notify1.service -p Type=notify -p ExecStopPost='/bin/touch /run/notify1' /tmp/notify1.sh
test -f /run/notify1

! systemd-run-wait notify2.service -p Type=notify -p ExecStopPost='/bin/touch /run/notify2' true
test -f /run/notify2

systemd-run-wait idle1.service -p Type=idle -p ExecStopPost='/bin/touch /run/idle1' true
test -f /run/idle1

! systemd-run-wait idle2.service -p Type=idle -p ExecStopPost='/bin/touch /run/idle2' false
test -f /run/idle2

systemd-analyze log-level info

echo OK > /testok

exit 0
