set(manager_core_src unit.c unit-printf.c job.c manager.c transaction.c
    load-fragment.c service.c  target.c
    snapshot.c socket.c timer.c path.c slice.c scope.c load-dropin.c execute.c
    kill.c dbus.c dbus-manager.c dbus-unit.c dbus-job.c dbus-service.c
    dbus-socket.c dbus-timer.c dbus-target.c dbus-snapshot.c dbus-path.c
    dbus-slice.c dbus-scope.c dbus-execute.c dbus-kill.c 
    smack-setup.c ima-setup.c locale-setup.c
    hostname-setup.c machine-id-setup.c mount-setup.c loopback-setup.c
    condition.c tcpwrap.c switch-root.c killall.c syscall-list.c
    audit-fd.c async.c async.h)

set(manager_core_src_linux dbus-cgroup.c cgroup.c swap.c dbus-swap.c mount.c
    dbus-mount.c device.c dbus-device.c automount.c dbus-automount.c
    selinux-access.c selinux-setup.c namespace.c)

add_library(manager-core ${manager_core_src})
target_link_libraries(manager-core initware-shared initware-units initware-label
    initware-dbus initware-id128)