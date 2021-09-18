add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/journald-gperf.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_SOURCE_DIR}/journald-gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/journald-gperf.c
    DEPENDS journald-gperf.gperf)
add_executable(svc.syslogd journald-console.c journald-kmsg.c journald-native.c
    journald-rate-limit.c journald-server.c journald-stream.c journald-syslog.c
    journald-wall.c journald.c
    ${CMAKE_CURRENT_BINARY_DIR}/journald-gperf.c)
target_include_directories(svc.syslogd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(svc.syslogd initware)

add_executable(syslogctl syslogctl.c)
target_link_libraries(syslogctl initware)