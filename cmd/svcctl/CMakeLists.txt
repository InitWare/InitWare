add_executable(svcctl svcctl.c svcctl-subr.c)
target_link_libraries(svcctl iw-shared iw-daemon iw-evlog
    iw-dbus iw-units iw-id128 PkgConfig::DBus)