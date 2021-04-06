add_subdirectory(manager)
add_subdirectory(rcng)

add_executable(iwctl systemctl.c)
target_link_libraries(iwctl initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)

add_executable(iwrun run.c)
target_link_libraries(iwrun initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)

install(TARGETS iwctl iwrun DESTINATION ${CMAKE_INSTALL_BINDIR})