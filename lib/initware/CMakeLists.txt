
add_library(iw-daemon daemon/sd-daemon.c)
target_include_directories(iw-daemon PUBLIC head)
target_link_libraries(iw-daemon internal ${MQ_Libs})

add_library(iw-id128 id128/sd-id128.c)
target_link_libraries(iw-id128 internal iw-shared)

add_library(iw-syslog syslog/catalog.c syslog/logs-show.c syslog/journal-file.c
    syslog/journal-send.c syslog/journal-vacuum.c syslog/journal-verify.c
    syslog/lookup3.c syslog/mmap-cache.c syslog/sd-journal.c)
target_link_libraries(iw-syslog internal iw-shared)
target_include_directories(iw-syslog PUBLIC syslog/head)

add_library(iw-login login/sd-login.c)
target_link_libraries(iw-login internal iw-shared ${EPoll_Compat_Libs})
target_include_directories(iw-login PUBLIC ${PROJECT_SOURCE_DIR}/cmd/login)

add_custom_command(
    OUTPUT bus-error-mapping.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_SOURCE_DIR}/bus/bus-error-mapping.gperf
	> bus-error-mapping.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bus/bus-error-mapping.gperf)

add_library(iw-bus bus/bus-control.c bus/bus-convenience.c bus/bus-creds.c
    bus/bus-dump.c bus/bus-error.c bus/bus-gvariant.c bus/bus-internal.c
    bus/bus-introspect.c bus/bus-match.c bus/bus-message.c bus/bus-objects.c
    bus/bus-signature.c bus/bus-socket.c bus/bus-type.c bus/bus-util.c
    bus/bus-kernel.c
    bus/sd-bus.c ${CMAKE_CURRENT_BINARY_DIR}/bus-error-mapping.c)
target_link_libraries(iw-bus internal iw-shared iw-id128 ${EPoll_Compat_Libs})
target_include_directories(iw-bus PRIVATE bus)

add_executable(svcbusctl bus/busctl.c)
target_link_libraries(svcbusctl iw-bus)

add_executable(example bus/example.c)
target_link_libraries(example iw-bus)

install(TARGETS iw-daemon iw-id128 iw-login iw-syslog
    DESTINATION ${CMAKE_INSTALL_LIBDIR})

if (USE_SYSTEMD_COMPAT_LINKS)
	configure_file(daemon/libsystemd-daemon.pc.in libsystemd-daemon.pc @ONLY)
	configure_file(id128/libsystemd-id128.pc.in libsystemd-id128.pc @ONLY)
	configure_file(login/libsystemd-login.pc.in libsystemd-login.pc @ONLY)
	configure_file(syslog/libsystemd-journal.pc.in libsystemd-journal.pc @ONLY)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsystemd-daemon.pc
		${CMAKE_CURRENT_BINARY_DIR}/libsystemd-id128.pc
		${CMAKE_CURRENT_BINARY_DIR}/libsystemd-login.pc
		${CMAKE_CURRENT_BINARY_DIR}/libsystemd-journal.pc
	    DESTINATION ${PKGCONF_DIR})
endif ()