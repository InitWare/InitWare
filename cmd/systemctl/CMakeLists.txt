add_executable(svcctl systemctl.c)
target_link_libraries(svcctl initware-shared initware-journal initware )