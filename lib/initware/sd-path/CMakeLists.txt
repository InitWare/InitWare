add_library(initware-path sd-path.c)
target_include_directories(initware-path PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-path initware-shared)