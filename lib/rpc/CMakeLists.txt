
add_library(iw-rpc rpc.c)
target_include_directories(iw-rpc PUBLIC head)
target_link_libraries(iw-rpc iw-shared iw-cjson)

add_executable(rpctest EXCLUDE_FROM_ALL test.c)
target_link_libraries(rpctest iw-rpc)

add_test(rpctest rpctest)