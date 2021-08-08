add_custom_command(
    OUTPUT schema_sqlite.h
    COMMAND ${CMAKE_COMMAND}
    ARGS -P ${PROJECT_SOURCE_DIR}/tools/MakeHeader.cmake ${CMAKE_CURRENT_SOURCE_DIR}/schema_sqlite.sql
        schema_sqlite.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/schema_sqlite.sql
    )
add_executable(evlogd evlogd.c sink_sqlite.c src_cred.c src_jdstream.c
    ${CMAKE_CURRENT_BINARY_DIR}/schema_sqlite.h)
target_link_libraries(evlogd iw-shared iw-ev iw-sqlite iw-id128)
target_include_directories(evlogd PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(evlog-cat cat.c)
target_link_libraries(evlog-cat iw-journal)