#!/bin/bash
set -ex

systemd-analyze set-log-level debug

systemctl start issue_14566_test
systemctl status issue_14566_test

leaked_pid=$(cat /leakedtestpid)

systemctl stop issue_14566_test

# Leaked PID will still be around if we're buggy.
# I personally prefer to see 42.
ps -p "$leaked_pid" && exit 42

systemd-analyze log-level info

echo OK > /testok

exit 0
