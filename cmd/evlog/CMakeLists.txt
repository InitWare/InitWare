add_custom_command(
    OUTPUT schema.h
    COMMAND ${CMAKE_COMMAND}
    ARGS -P ${PROJECT_SOURCE_DIR}/tools/MakeHeader.cmake ${CMAKE_CURRENT_SOURCE_DIR}/schema.sql
        schema.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/schema.sql
    )
add_executable(evlogd evlogd.c backend.c jd_stream.c ${CMAKE_CURRENT_BINARY_DIR}/schema.h)
target_link_libraries(evlogd iw-shared iw-ev iw-sqlite iw-id128)
target_include_directories(evlogd PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(evlog-cat cat.c)
target_link_libraries(evlog-cat iw-journal)