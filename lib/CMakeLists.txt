add_subdirectory(compat)

set(Ev_src ${PROJECT_SOURCE_DIR}/vendor/libev)
add_library(initware-ev STATIC ${Ev_src}/ev.c)
target_compile_definitions(initware-ev PUBLIC EV_STANDALONE=1)
target_include_directories(initware-ev PUBLIC ${Ev_src})

add_subdirectory(shared)
add_subdirectory(initware-rpc)
add_subdirectory(libinitware-daemon)
add_subdirectory(libinitware-id128)