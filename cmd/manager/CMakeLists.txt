if (USE_SYSTEMD_COMPAT_LINKS)
	configure_file(systemd.pc.in systemd.pc @ONLY)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd.pc
	    DESTINATION ${PKGCONF_DIR})
endif ()

add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    COMMAND m4 -P < ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4)

add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    COMMAND awk -f ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf-nulstr.awk
      < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf)

set(MANAGER_SRC dbus/bus.c dbus/dbus-execute.c dbus/dbus-job.c dbus/dbus-kill.c
    dbus/dbus-manager.c dbus/dbus-path.c dbus/dbus-scope.c dbus/dbus-service.c
    dbus/dbus-slice.c dbus/dbus-snapshot.c dbus/dbus-socket.c dbus/dbus-target.c
    dbus/dbus-timer.c dbus/dbus-unit.c dbus/dbus-delegate.c

    async.c async.h audit-fd.c condition.c
    delegate.c event.c execute.c job.c kill.c
    load-dropin.c load-fragment.c locale-setup.c manager.c
    path.c scope.c service.c slice.c snapshot.c socket.c target.c
    timer.c transaction.c unit.c unit-printf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c)

if(Use_Libudev OR Use_Libdevattr)
	list(APPEND MANAGER_SRC dbus/dbus-device.c device.c)
endif()

if(Use_KQProc)
	list(APPEND MANAGER_SRC ptgroup/kqproc.c ptgroup/ptgroup.c)
endif()

if(Sys_Plat_Linux)
	if(Use_Libudev OR Use_Libdevattr)
		list(APPEND MANAGER_SRC swap.c dbus/dbus-swap.c)
	endif()
	list(APPEND MANAGER_SRC automount.c dbus/dbus-automount.c dbus/dbus-cgroup.c
	    dbus/dbus-mount.c linux/cgroup.c linux/loopback-setup.c mount.c linux/mount-setup.c init/selinux-setup.c init/switch-root.c
	    namespace.c selinux-access.c)
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