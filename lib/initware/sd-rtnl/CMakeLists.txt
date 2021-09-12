add_library(initware-rtnl local-addresses.c rtnl-message.c rtnl-types.c
    rtnl-util.c sd-rtnl.c)
target_include_directories(initware-rtnl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-rtnl initware-basic)