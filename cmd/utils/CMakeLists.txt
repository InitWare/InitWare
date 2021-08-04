add_executable(svcanalyse analyse.c)
target_link_libraries(svcanalyse iw-shared iw-daemon
    iw-dbus iw-units iw-id128 PkgConfig::DBus)

add_executable(svcrun run.c)
target_link_libraries(svcrun iw-shared iw-daemon
    iw-dbus iw-units iw-id128 PkgConfig::DBus)

add_executable(svcnotify notify.c)
target_link_libraries(svcnotify iw-shared iw-daemon)

install(TARGETS svcanalyse svcctl svcrun DESTINATION ${CMAKE_INSTALL_BINDIR})