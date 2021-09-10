add_library(initware-login sd-login.c)
target_include_directories(initware-login PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-login initware-shared)