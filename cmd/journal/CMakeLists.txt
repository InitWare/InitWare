add_library(initware-journal catalog.c compress.c
    journal-file.c journal-send.c journal-vacuum.c journal-verify.c lookup3.c
    mmap-cache.c sd-journal.c)
target_link_libraries(initware-journal initware-shared)