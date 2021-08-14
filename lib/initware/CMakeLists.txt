
add_library(iw-daemon daemon/sd-daemon.c)
target_include_directories(iw-daemon PUBLIC head)
target_link_libraries(iw-daemon internal ${MQ_Libs})

add_library(iw-id128 id128/sd-id128.c)
target_link_libraries(iw-id128 internal iw-shared)

add_library(iw-evlog evlog/catalog.c evlog/logs-show.c evlog/journal-file.c
    evlog/journal-send.c evlog/journal-vacuum.c evlog/journal-verify.c
    evlog/lookup3.c evlog/mmap-cache.c evlog/sd-journal.c)
target_link_libraries(iw-evlog internal iw-shared)
target_include_directories(iw-evlog PUBLIC evlog/head)