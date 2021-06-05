add_subdirectory(iwctl)
add_subdirectory(manager)
add_subdirectory(rcng)
add_subdirectory(login)

set(DB2MDSRC ${PROJECT_SOURCE_DIR}/vendor/docbook2mdoc)
add_executable(docbook2mdoc EXCLUDE_FROM_ALL ${DB2MDSRC}/docbook2mdoc.c
    ${DB2MDSRC}/macro.c ${DB2MDSRC}/main.c ${DB2MDSRC}/node.c
    ${DB2MDSRC}/parse.c ${DB2MDSRC}/reorg.c ${DB2MDSRC}/tree.c
    ${DB2MDSRC}/xmalloc.c)
target_link_libraries(docbook2mdoc compat)

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