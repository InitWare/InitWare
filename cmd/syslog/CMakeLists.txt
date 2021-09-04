add_custom_command(OUTPUT journald-gperf.c
    COMMAND gperf < ${CMAKE_CURRENT_SOURCE_DIR}/journald-gperf.gperf
	> journald-gperf.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/journald-gperf.gperf)

add_executable(svc.syslogd journald.c journald-console.c journald-kmsg.c
    journald-native.c journald-rate-limit.c journald-server.c journald-stream.c
    journald-syslog.c ${CMAKE_CURRENT_BINARY_DIR}/journald-gperf.c)
target_link_libraries(svc.syslogd iw-syslog iw-daemon iw-id128)
target_include_directories(svc.syslogd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(syslogctl journalctl.c)
target_link_libraries(syslogctl iw-shared iw-syslog iw-id128)

add_executable(syslogcat cat.c)
target_link_libraries(syslogcat iw-shared iw-syslog)

install(TARGETS svc.syslogd RUNTIME DESTINATION ${INSTALL_PKGLIBEXEC_DIR})
install(TARGETS syslogcat syslogctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
