add_executable(busctl busctl-introspect.c busctl.c)
target_link_libraries(busctl initware)