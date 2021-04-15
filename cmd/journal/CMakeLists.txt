add_library(journal-internal journald-kmsg.c journald-kmsg.h journald-syslog.c
    journald-syslog.h journald-stream.c journald-stream.h journald-server.c
    journald-server.h journald-console.c journald-console.h journald-native.c
    journald-native.h journald-rate-limit.c journald-rate-limit.h)
target_link_libraries(journal-internal initware-shared initware-journal)

add_executable(iw.journald journald.c journald-server.h)
target_link_libraries(iw.journald journal-internal initware-daemon
    initware-id128)