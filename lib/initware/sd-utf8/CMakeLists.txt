add_library(initware-utf8 sd-utf8.c)
target_include_directories(initware-utf8 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-utf8 initware-shared)