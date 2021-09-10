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

add_executable(svc.schedulerd cgroup.c dbus-cgroup.c dbus-execute.c dbus-job.c
    dbus-kill.c dbus-manager.c dbus-path.c dbus-scope.c dbus-service.c
    dbus-slice.c dbus-snapshot.c dbus-socket.c dbus-target.c dbus-timer.c
    dbus-unit.c dbus.c emergency-action.c execute.c job.c ima-setup.c kill.c load-dropin.c
    load-fragment.c main.c manager.c path.c scope.c selinux-access.c selinux-setup.c service.c show-status.c
    slice.c smack-setup.c snapshot.c socket.c target.c timer.c transaction.c unit-printf.c
    unit.c
    hostname-setup.c  kmod-setup.c locale-setup.c loopback-setup.c machine-id-setup.c mount-setup.c

    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf.c
    ${CMAKE_CURRENT_BINARY_DIR}/load-fragment-gperf-nulstr.c   )
target_include_directories(svc.schedulerd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(svc.schedulerd initware)