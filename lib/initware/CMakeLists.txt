add_subdirectory(sd-bus)
add_subdirectory(sd-daemon)
add_subdirectory(sd-event)
add_subdirectory(sd-id128)
add_subdirectory(syslog)
add_subdirectory(sd-login)
add_subdirectory(sd-path)
add_subdirectory(sd-utf8)
if (SVC_PLATFORM_Linux)
	add_subdirectory(sd-rtnl)
	set(SD_RTNL initware-rtnl)
endif ()

add_library(initware empty.c)
target_link_libraries(initware PUBLIC initware-bus initware-daemon ${SD_RTNL}
    initware-event initware-id128 initware-syslog initware-login initware-path
    initware-utf8)