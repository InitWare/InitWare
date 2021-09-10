add_library(initware-id128 sd-id128.c)
target_include_directories(initware-id128 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-id128 initware-shared)