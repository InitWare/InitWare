#!/bin/bash
TEST_DESCRIPTION="test that ExecStopPost= is always run"

. $TEST_BASE_DIR/test-functions

check_result_qemu() {
    ret=1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    [[ -e $TESTDIR/root/testok ]] && ret=0
    [[ -f $TESTDIR/root/failed ]] && cp -a $TESTDIR/root/failed $TESTDIR
    [[ -f $TESTDIR/root/var/log/journal ]] && cp -a $TESTDIR/root/var/log/journal $TESTDIR
    umount $TESTDIR/root
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}

test_run() {
    if run_qemu; then
        check_result_qemu || return 1
    else
        dwarn "can't run QEMU, skipping"
    fi
    if check_nspawn; then
        run_nspawn
        check_result_nspawn || return 1
    else
        dwarn "can't run systemd-nspawn, skipping"
    fi
    return 0
}

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install false true env touch

        # mask some services that we do not want to run in these tests
        ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
        ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

        # setup policy for Type=dbus test
        mkdir -p $initdir/etc/dbus-1/system.d
        cat > $initdir/etc/dbus-1/system.d/systemd.test.ExecStopPost.conf <<EOF
<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
        "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
    <policy user="root">
        <allow own="systemd.test.ExecStopPost"/>
    </policy>
</busconfig>
EOF

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/bin/bash -x /testsuite.sh
Type=oneshot
StandardOutput=tty
StandardError=tty
NotifyAccess=all
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

do_test "$@"
