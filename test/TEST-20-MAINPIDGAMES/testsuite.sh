#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

systemctl_show_value() {
    systemctl show "$@" | cut -d = -f 2-
}

systemd-analyze set-log-level debug

test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Start a test process inside of our own cgroup
sleep infinity &
INTERNALPID=$!
disown

# Start a test process outside of our own cgroup
systemd-run -p User=test --unit=sleep.service /bin/sleep infinity
EXTERNALPID=`systemctl_show_value -p MainPID sleep.service`

# Update our own main PID to the external test PID, this should work
systemd-notify MAINPID=$EXTERNALPID
test `systemctl_show_value -p MainPID testsuite.service` -eq $EXTERNALPID

# Update our own main PID to the internal test PID, this should work, too
systemd-notify MAINPID=$INTERNALPID
test `systemctl_show_value -p MainPID testsuite.service` -eq $INTERNALPID

# Update it back to our own PID, this should also work
systemd-notify MAINPID=$$
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Try to set it to PID 1, which it should ignore, because that's the manager
systemd-notify MAINPID=1
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Try to set it to PID 0, which is invalid and should be ignored
systemd-notify MAINPID=0
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Try to set it to a valid but non-existing PID, which should be ignored. (Note
# that we set the PID to a value well above any known /proc/sys/kernel/pid_max,
# which means we can be pretty sure it doesn't exist by coincidence)
systemd-notify MAINPID=1073741824
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Change it again to the external PID, without priviliges this time. This should be ignored, because the PID is from outside of our cgroup and we lack privileges.
systemd-notify --uid=1000 MAINPID=$EXTERNALPID
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

# Change it again to the internal PID, without priviliges this time. This should work, as the process is on our cgroup, and that's enough even if we lack privileges.
systemd-notify --uid=1000 MAINPID=$INTERNALPID
test `systemctl_show_value -p MainPID testsuite.service` -eq $INTERNALPID

# Update it back to our own PID, this should also work
systemd-notify --uid=1000 MAINPID=$$
test `systemctl_show_value -p MainPID testsuite.service` -eq $$

cat >/tmp/mainpid.sh <<EOF
#!/bin/bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=\$!
disown

sleep infinity &
disown

echo \$MAINPID > /run/mainpidsh/pid
EOF
chmod +x /tmp/mainpid.sh

cat > /etc/systemd/system/mainpidsh.service <<EOF
[Unit]
Description=MainPID test 1 service

[Service]
StandardOutput=tty
StandardError=tty
Type=forking
RuntimeDirectory=mainpidsh
PIDFile=/run/mainpidsh/pid
ExecStart=/tmp/mainpid.sh
EOF

systemctl daemon-reload
systemctl start mainpidsh.service
test `systemctl_show_value -p MainPID mainpidsh.service` -eq `cat /run/mainpidsh/pid`

cat >/tmp/mainpid2.sh <<EOF
#!/bin/bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=\$!
disown

sleep infinity &
disown

echo \$MAINPID > /run/mainpidsh2/pid
chown 1001:1001 /run/mainpidsh2/pid
EOF
chmod +x /tmp/mainpid2.sh

cat > /etc/systemd/system/mainpidsh2.service <<EOF
[Unit]
Description=MainPID test 2 service

[Service]
StandardOutput=tty
StandardError=tty
Type=forking
RuntimeDirectory=mainpidsh2
PIDFile=/run/mainpidsh2/pid
ExecStart=/tmp/mainpid2.sh
EOF

systemctl daemon-reload
systemctl start mainpidsh2.service
test `systemctl_show_value -p MainPID mainpidsh2.service` -eq `cat /run/mainpidsh2/pid`

cat >/dev/shm/mainpid3.sh <<EOF
#!/bin/bash

set -eux
set -o pipefail

sleep infinity &
disown

sleep infinity &
disown

sleep infinity &
disown

# Let's try to play games, and link up a privileged PID file
ln -s ../mainpidsh/pid /run/mainpidsh3/pid

# Quick assertion that the link isn't dead
test -f /run/mainpidsh3/pid
EOF
chmod 755 /dev/shm/mainpid3.sh

cat > /etc/systemd/system/mainpidsh3.service <<EOF
[Unit]
Description=MainPID test 3 service

[Service]
StandardOutput=tty
StandardError=tty
Type=forking
RuntimeDirectory=mainpidsh3
PIDFile=/run/mainpidsh3/pid
User=test
TimeoutStartSec=2s
ExecStart=/dev/shm/mainpid3.sh
EOF

systemctl daemon-reload
! systemctl start mainpidsh3.service

# Test that this failed due to timeout, and not some other error
test `systemctl_show_value -p Result mainpidsh3.service` = timeout

systemd-analyze set-log-level info

echo OK > /testok

exit 0
