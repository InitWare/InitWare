add_executable(wait4pipe wait4pipe.c)
target_link_libraries(wait4pipe compat)

add_executable(rcng2unit rcng2unit.c)


install(TARGETS wait4pipe rcng2unit DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
install(SCRIPT rcng-generator.sh DESTINATION ${systemgeneratordir})