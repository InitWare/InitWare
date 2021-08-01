
add_library(initware-id128 sd-id128.c)
target_include_directories(initware-id128 PUBLIC head)
target_link_libraries(initware-id128 internal initware-shared)