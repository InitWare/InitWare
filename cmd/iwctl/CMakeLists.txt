add_executable(iwctl iwctl.c iwctlsubr.c)
target_link_libraries(iwctl iw-shared iw-daemon
    iw-dbus iw-units iw-id128 PkgConfig::DBus)