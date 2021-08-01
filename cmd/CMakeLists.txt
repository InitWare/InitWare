add_subdirectory(iwctl)
add_subdirectory(manager)
add_subdirectory(rcng)
add_subdirectory(login)

add_executable(iwanalyse analyse.c)
target_link_libraries(iwanalyse iw-shared iw-daemon
    iw-dbus iw-units iw-id128 PkgConfig::DBus)

add_executable(iwrun run.c)
target_link_libraries(iwrun iw-shared iw-daemon
    iw-dbus iw-units iw-id128 PkgConfig::DBus)

add_executable(iwnotify notify.c)
target_link_libraries(iwnotify iw-shared iw-daemon)

add_executable(init init.c)

install(TARGETS init DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS iwanalyse iwctl iwrun DESTINATION ${CMAKE_INSTALL_BINDIR})