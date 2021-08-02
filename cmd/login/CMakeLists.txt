add_custom_command(
  OUTPUT logind-gperf.c
  COMMAND gperf < ${CMAKE_CURRENT_SOURCE_DIR}/logind-gperf.gperf
    > logind-gperf.c
  DEPENDS  ${CMAKE_CURRENT_SOURCE_DIR}/logind-gperf.gperf)

set(login_srcs logind-core.c logind-dbus.c logind-device.c
    logind-device.h logind-action.c
    logind-action.h logind-seat.c logind-seat.h logind-session.c
    logind-session.h logind-session-device.c logind-session-device.h
    logind-user.c logind-user.h logind-inhibit.c logind-inhibit.h
    logind-session-dbus.c logind-seat-dbus.c logind-user-dbus.c logind-acl.h
    login-shared.c login-shared.h ${CMAKE_CURRENT_BINARY_DIR}/logind-gperf.c)

if(Use_Libudev)
    list(APPEND login_srcs logind-button.c)
endif()

add_library(login-core ${login_srcs})
target_link_libraries(login-core iw-shared iw-dbus iw-daemon
  iw-label ${UDev_Libs})
target_include_directories(login-core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(iw.logind logind.c)
target_link_libraries(iw.logind login-core)

add_executable(user-sessions user-sessions.c)
target_link_libraries(user-sessions iw-shared)
install(TARGETS iw.logind user-sessions RUNTIME DESTINATION ${RelDir_PkgLibExec})

set(loginctl_srcs loginctl.c)
if(Use_Libudev)
    list(APPEND loginctl_srcs sysfs-show.c)
endif()

add_executable(iwloginctl ${loginctl_srcs})
target_link_libraries(iwloginctl iw-shared iw-dbus ${UDev_Libs})
install(TARGETS iwloginctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(Use_PAM)
    add_library(initware_pam SHARED pam-module.c)
    target_link_libraries(initware_pam iw-shared iw-dbus pam)
endif()
