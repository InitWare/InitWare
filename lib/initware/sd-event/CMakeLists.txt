add_library(initware-event sd-event.c)
target_include_directories(initware-event PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-event initware-shared)