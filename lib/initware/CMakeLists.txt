add_subdirectory(sd-bus)
add_subdirectory(sd-daemon)
add_subdirectory(sd-event)
add_subdirectory(sd-id128)
add_subdirectory(sd-login)
add_subdirectory(sd-path)
add_subdirectory(sd-utf8)

add_library(initware empty.c)
target_link_libraries(initware PUBLIC initware-bus initware-daemon
    initware-event initware-id128 initware-login initware-path initware-utf8)