#add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
#    COMMAND m4 -P < ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
#      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
#    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4)

build_m4(${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    COMMAND awk -f ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf-nulstr.awk
      < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

if (SVC_USE_KQProc)
#	list(APPEND MANAGER_SRCS ptgroup/kqproc.c ptgroup/ptgroup.c)
endif ()

add_executable(svc.schedulerd cgroup.c dbus-cgroup.c dbus-execute.c dbus-job.c
    dbus-kill.c dbus-manager.c dbus-path.c dbus-scope.c dbus-service.c
    dbus-slice.c dbus-snapshot.c dbus-socket.c dbus-target.c dbus-timer.c
    dbus-unit.c dbus-util.c dbus.c emergency-action.c execute.c job.c ima-setup.c kill.c
    load-dropin.c load-fragment.c main.c manager.c path.c scope.c
    selinux-access.c selinux-setup.c service.c show-status.c slice.c
    smack-setup.c snapshot.c socket.c target.c timer.c transaction.c
    unit-printf.c unit.c
    hostname-setup.c killall.c kmod-setup.c locale-setup.c loopback-setup.c
    machine-id-setup.c mount-setup.c namespace.c
    ${MANAGER_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c)

target_include_directories(svc.schedulerd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(svc.schedulerd initware)

if (SVC_USE_PAM)
	target_link_libraries(svc.schedulerd pam)
endif ()

set(MANIFESTS_IN emergency.service.in systemd-halt.service.in
    systemd-kexec.service.in halt-local.service.in
    systemd-hibernate-resume@.service.in systemd-reboot.service.in
    rc-local.service.in systemd-hibernate.service.in rescue.service.in
    systemd-hybrid-sleep.service.in user@.service.in)
set(MANIFESTS basic.target bluetooth.target cryptsetup-pre.target
    cryptsetup.target emergency.target final.target getty-pre.target
    getty.target graphical.target halt.target hibernate.target
    hybrid-sleep.target kexec.target local-fs-pre.target local-fs.target
    machine.slice machines.target multi-user.target network-online.target
    network-pre.target network.target nss-lookup.target nss-user-lookup.target
    paths.target poweroff.target printer.target reboot.target
    remote-cryptsetup.target remote-fs-pre.target remote-fs.target rescue.target
    rpcbind.target shutdown.target sigpwr.target sleep.target -.slice
    slices.target smartcard.target sockets.target sound.target suspend.target
    swap.target sysinit.target system.slice system-update.target timers.target
    time-sync.target tmp.mount umount.target user.slice)

install_manifests(SYSTEM_IN ${MANIFESTS_IN} SYSTEM ${MANIFESTS})
install(TARGETS svc.schedulerd DESTINATION ${SVC_PKGLIBEXECDIR})

# pkg-config file
configure_file(InitWare.pc.in InitWare.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/InitWare.pc
    DESTINATION ${PKGCONF_DIR})

# D-Bus & PolicyKit
configure_file(org.InitWare.Scheduler1.conf.in org.InitWare.Scheduler1.conf)
configure_file(org.InitWare.Scheduler1.policy.in
    org.InitWare.Scheduler1.policy)
configure_file(org.InitWare.Scheduler1.service.in
    org.InitWare.Scheduler1.service)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.InitWare.Scheduler1.service
    DESTINATION ${SVC_DBUSSERVICESDIR}
    RENAME ${SVC_DBUS_BUSNAME}.service)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.InitWare.Scheduler1.policy
    DESTINATION ${SVC_POLKITACTIONDIR}
    RENAME ${SVC_DBUS_BUSNAME}.policy)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.InitWare.Scheduler1.conf
    DESTINATION ${SVC_DBUSCONFDIR}
    RENAME ${SVC_DBUS_BUSNAME}.conf)