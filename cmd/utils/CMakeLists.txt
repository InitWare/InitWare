add_executable(svccgls cgls.c)
target_link_libraries(svccgls initware-shared initware)

add_executable(svcrun run.c)
target_link_libraries(svcrun initware-shared initware)