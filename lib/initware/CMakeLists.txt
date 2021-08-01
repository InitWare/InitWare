
add_library(iw-daemon daemon/sd-daemon.c)
target_include_directories(iw-daemon PUBLIC head)
target_link_libraries(iw-daemon internal ${MQ_Libs})

add_library(iw-id128 id128/sd-id128.c)
target_link_libraries(iw-id128 internal iw-shared)