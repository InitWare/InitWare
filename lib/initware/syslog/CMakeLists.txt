add_library(initware-syslog catalog.c compress.c
    journal-file.c journal-send.c journal-vacuum.c journal-verify.c lookup3.c
    mmap-cache.c sd-journal.c)
target_include_directories(initware-syslog PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(initware-syslog initware-shared)