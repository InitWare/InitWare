add_executable(svc.schedulerd bus-endpoint.c bus-policy.c busname.c)
target_link_libraries(svc.schedulerd initware)