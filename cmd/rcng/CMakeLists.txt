add_executable(wait4pipe wait4pipe.c)
target_link_libraries(wait4pipe compat)

add_executable(rcng2unit rcng2unit.c)
target_link_libraries(rcng2unit initware-shared)

install(TARGETS wait4pipe rcng2unit DESTINATION ${RelDir_PkgLibExec})
install(PROGRAMS rcng-generator.sh DESTINATION ${systemgeneratordir})

if(Sys_Plat_NetBSD)
    install(PROGRAMS netbsd/runrcng.sh DESTINATION ${RelDir_PkgLibExec})
endif()

install(FILES bootdone.service DESTINATION ${systemunitdir})