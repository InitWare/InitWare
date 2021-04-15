add_executable(iwctl iwctl.c iwctlsubr.c)
target_link_libraries(iwctl initware-shared initware-daemon
    initware-dbus initware-units initware-id128 PkgConfig::DBus)