add_library(initware-daemon sd-daemon.c)
target_include_directories(initware-daemon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-daemon initware-shared)