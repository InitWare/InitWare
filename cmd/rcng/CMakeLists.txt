add_executable(wait4pipe wait4pipe.c)
target_link_libraries(wait4pipe compat)

add_executable(rcng2unit rcng2unit.c)
target_link_libraries(rcng2unit initware-shared)

install(TARGETS wait4pipe rcng2unit DESTINATION ${RelDir_PkgLibExec})
install(SCRIPT rcng-generator.sh DESTINATION ${systemgeneratordir})