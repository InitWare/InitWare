
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