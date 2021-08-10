add_custom_command(
  OUTPUT journald-gperf.c
  COMMAND gperf < ${CMAKE_CURRENT_SOURCE_DIR}/journald-gperf.gperf
    > journald-gperf.c
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/journald-gperf.gperf)

add_executable(evlogd journald.c journald-console.c journald-kmsg.c
    journald-native.c journald-rate-limit.c journald-server.c journald-stream.c
    journald-syslog.c ${CMAKE_CURRENT_BINARY_DIR}/journald-gperf.c)
target_link_libraries(evlogd iw-evlog iw-daemon iw-id128)
target_include_directories(evlogd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(evlogctl journalctl.c)
target_link_libraries(evlogctl iw-shared iw-evlog iw-id128)

add_executable(evlogcat cat.c)
target_link_libraries(evlogcat iw-shared iw-evlog)

install(TARGETS evlogd RUNTIME DESTINATION ${INSTALL_PKGLIBEXEC_DIR})
install(TARGETS evlogcat evlogctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
