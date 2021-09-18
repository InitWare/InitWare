add_executable(svcctl svcctl.c)
target_link_libraries(svcctl initware-shared initware)

install(TARGETS svcctl DESTINATION ${CMAKE_INSTALL_BINDIR})