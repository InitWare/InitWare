add_subdirectory(busctl)
if (SVC_PLATFORM_BSD)
	add_subdirectory(cgrpfs)
endif ()
add_subdirectory(schedulerd)
add_subdirectory(session)
add_subdirectory(svcctl)
add_subdirectory(syslog)
add_subdirectory(utils)