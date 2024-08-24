add_library(initware-shared cgroup-show.c cjson-util.c fdset.c logs-show.c pretty-print.c)
target_include_directories(initware-shared
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(initware-shared initware-basic initware iw-cjson)