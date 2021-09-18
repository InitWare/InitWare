add_subdirectory(syslogd)

set(MANIFESTS_IN system-log-catalog-update.service.in
  system-log-flush.service.in system-log.service.in)
set(MANIFESTS system-log.socket)

# if use microhttpd
list(APPEND MANIFESTS_IN system-log-webserver.service.in)
list(APPEND MANIFESTS system-log-webserver.socket)
# endif

add_executable(syslogctl syslogctl.c)
target_link_libraries(syslogctl initware)

install(TARGETS syslogctl DESTINATION ${CMAKE_INSTALL_BINDIR})
install_manifests(SYSTEM_IN ${MANIFESTS_IN} SYSTEM ${MANIFESTS})