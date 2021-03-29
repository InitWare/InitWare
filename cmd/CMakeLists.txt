add_subdirectory(manager)

add_executable(iwctl systemctl.c)
target_link_libraries(iwctl initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)
