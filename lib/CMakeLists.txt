add_subdirectory(compat)
add_subdirectory(shared)
add_subdirectory(rpc)
add_subdirectory(initware)

install(DIRECTORY ${PROJECT_SOURCE_DIR}/head/systemd
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (USE_SYSTEMD_COMPAT_LINKS)
	configure_file(libsystemd.pc.in libsystemd.pc @ONLY)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsystemd.pc
	    DESTINATION ${PKGCONF_DIR})
endif ()