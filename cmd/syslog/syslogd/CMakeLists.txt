add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gperf.c
    COMMAND ${GPERF} < ${CMAKE_CURRENT_SOURCE_DIR}/gperf.gperf
      > ${CMAKE_CURRENT_BINARY_DIR}/gperf.c
    DEPENDS gperf.gperf)
add_executable(svc.syslogd console.c kmsg.c native.c rate-limit.c server.c
    stream.c syslog.c wall.c syslogd.c ${CMAKE_CURRENT_BINARY_DIR}/gperf.c)
target_include_directories(svc.syslogd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(svc.syslogd initware)
install(TARGETS svc.syslogd DESTINATION ${SVC_PKGLIBEXECDIR})