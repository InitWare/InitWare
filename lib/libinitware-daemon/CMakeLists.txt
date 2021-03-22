
add_library(initware-daemon sd-daemon.c)
target_include_directories(initware-daemon PUBLIC head)
target_link_libraries(initware-daemon internal)