add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
  COMMAND m4 -P < ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
    > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf.gperf.m4
  )

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
  COMMAND gperf < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
  )

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
  COMMAND awk -f ${CMAKE_CURRENT_SOURCE_DIR}/load-fragment-gperf-nulstr.awk
    < ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
    > ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.gperf
  )

set(manager_core_src unit.c unit-printf.c job.c manager.c transaction.c
    load-fragment.c service.c  target.c
    snapshot.c socket.c timer.c path.c slice.c scope.c load-dropin.c execute.c
    kill.c dbus.c dbus-manager.c dbus-unit.c dbus-job.c dbus-service.c
    dbus-socket.c dbus-timer.c dbus-target.c dbus-snapshot.c dbus-path.c
    dbus-slice.c dbus-scope.c dbus-execute.c dbus-kill.c
    smack-setup.c ima-setup.c locale-setup.c
    hostname-setup.c machine-id-setup.c
    condition.c tcpwrap.c killall.c
    audit-fd.c async.c async.h
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c)

if(Use_Libudev OR Use_Libdevattr)
  list(APPEND manager_core_src dbus-device.c device.c)
endif()

set(manager_core_src_linux dbus-cgroup.c cgroup.c swap.c dbus-swap.c mount.c
    dbus-mount.c device.c dbus-device.c automount.c dbus-automount.c
    selinux-access.c selinux-setup.c namespace.c c mount-setup.c
    loopback-setup.c switch-root.c syscall-list.c)

add_library(manager-core ${manager_core_src})
target_include_directories(manager-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(manager-core initware-shared initware-units initware-label
    initware-dbus initware-id128 initware-daemon ${UDev_Libs} ${Cap_Libs}
    PkgConfig::DBus Threads::Threads)

add_executable(iw.manager main.c)
target_link_libraries(iw.manager manager-core)