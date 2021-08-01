add_subdirectory(iwctl)
add_subdirectory(manager)
add_subdirectory(rcng)
add_subdirectory(login)

add_executable(iwanalyse analyse.c)
target_link_libraries(iwanalyse initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)

add_executable(iwrun run.c)
target_link_libraries(iwrun initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)

add_executable(iwnotify notify.c)
target_link_libraries(iwnotify initware-shared initware-daemon)

add_executable(init init.c)

install(TARGETS init DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS iwanalyse iwctl iwrun DESTINATION ${CMAKE_INSTALL_BINDIR})