add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    COMMAND m4 -P < ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4)

add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    COMMAND gperf < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    COMMAND awk -f ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf-nulstr.awk
      < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

set(MANAGER_SRC async.c async.h audit-fd.c condition.c
    dbus.c dbus-execute.c dbus-job.c dbus-kill.c dbus-manager.c dbus-path.c
    dbus-scope.c dbus-service.c dbus-slice.c dbus-snapshot.c dbus-socket.c
    dbus-target.c dbus-timer.c dbus-unit.c
    event.c execute.c hostname-setup.c ima-setup.c job.c kill.c killall.c
    load-dropin.c load-fragment.c locale-setup.c machine-id-setup.c manager.c
    path.c scope.c service.c slice.c smack-setup.c snapshot.c socket.c target.c
    timer.c transaction.c unit.c unit-printf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c)

if(Use_Libudev OR Use_Libdevattr)
	list(APPEND MANAGER_SRC dbus-device.c device.c)
endif()

if(Use_KQProc)
	list(APPEND MANAGER_SRC ptgroup/kqproc.c ptgroup/ptgroup.c)
endif()

if(Sys_Plat_Linux)
	if(Use_Libudev OR Use_Libdevattr)
		list(APPEND MANAGER_SRC swap.c dbus-swap.c)
	endif()
	list(APPEND MANAGER_SRC automount.c dbus-automount.c dbus-cgroup.c
	    dbus-mount.c linux/cgroup.c loopback-setup.c mount.c mount-setup.c
	    namespace.c selinux-access.c selinux-setup.c switch-root.c)
endif()

add_executable(svc.managerd main.c ${MANAGER_SRC})
target_include_directories(svc.managerd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(svc.managerd iw-shared iw-units iw-label
    iw-dbus iw-id128 iw-daemon iw-cjson iw-ev
    ${UDev_Libs} PkgConfig::DBus Threads::Threads)
if(Use_PAM)
	target_link_libraries(svc.managerd pam)
endif()

install(TARGETS svc.managerd RUNTIME DESTINATION ${INSTALL_PKGLIBEXEC_DIR})

configure_file(org.InitWare.Scheduler1.service.in
  org.InitWare.Scheduler1.service)
configure_file(org.InitWare.Scheduler1.conf.in org.InitWare.Scheduler1.conf)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.InitWare.Scheduler1.service
    DESTINATION ${INSTALL_DBUSSERVICES_DIR}
    RENAME ${SCHEDULER_DBUS_BUSNAME}.service)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.InitWare.Scheduler1.conf
    DESTINATION ${INSTALL_DBUSCONF_DIR}
    RENAME ${SCHEDULER_DBUS_BUSNAME}.conf)