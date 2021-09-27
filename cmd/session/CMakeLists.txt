add_executable(sessionctl sessionctl.c sysfs-show.c)
target_link_libraries(sessionctl initware)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gperf.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_SOURCE_DIR}/sessiond/gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/gperf.c
    DEPENDS sessiond/gperf.gperf)
add_executable(svc.sessiond sessiond/action.c sessiond/core.c sessiond/dbus.c
    sessiond/inhibit.c sessiond/sessiond.c sessiond/seat-dbus.c sessiond/seat.c
    sessiond/session-dbus.c sessiond/session.c sessiond/user-dbus.c
    sessiond/user.c
    ${CMAKE_CURRENT_BINARY_DIR}/gperf.c)
target_include_directories(svc.sessiond
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sessiond>)
target_link_libraries(svc.sessiond initware)

if (SVC_USE_PAM)
	add_library(pam_initware SHARED pam/pam_initware.c)
	target_link_libraries(pam_initware initware pam)
	set_target_properties(pam_initware PROPERTIES PREFIX "")
	install(TARGETS pam_initware
	    DESTINATION ${CMAKE_INSTALL_LIBDIR}/security)
endif ()