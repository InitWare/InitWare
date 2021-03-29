
add_library(initware-rpc rpc.c)
target_include_directories(initware-rpc PUBLIC head)
target_link_libraries(initware-rpc initware-shared initware-cjson)