add_library(initware-bus bus-common-errors.c bus-control.c bus-convenience.c
    bus-creds.c bus-dump.c bus-error.c bus-gvariant.c bus-internal.c
    bus-introspect.c bus-match.c bus-message.c bus-objects.c bus-signature.c
    bus-slot.c bus-socket.c bus-track.c bus-type.c bus-util.c sd-bus.c)
target_include_directories(initware-bus PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(initware-bus initware-shared)