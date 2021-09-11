add_library(initware-shared nothing.c)
target_include_directories(initware-shared
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(initware-shared initware-basic)