set (DOCBOOKS iw_rcng.7.xml)

foreach(DOCBOOK_IN ${DOCBOOKS})
    get_filename_component(MAN_BASE ${DOCBOOK_IN} NAME_WLE)
    message("Build Docbook ${MAN_BASE}")
  
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE}
        COMMAND $<TARGET_FILE:docbook2mdoc> ${DOCBOOK_IN}
          > ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${DOCBOOK_IN} $<TARGET_FILE:docbook2mdoc>
        COMMENT "Generating MDoc manual page ${MAN_BASE}")
  
    list(APPEND MDOCS ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE})
endforeach()

foreach(MAN_IN ${MDOCS})
    get_filename_component(MAN_BASE ${MAN_IN} NAME)
    get_filename_component(MAN_EXT ${MAN_IN} LAST_EXT)
    set(HTML_OUT ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE}.html)
    string(SUBSTRING ${MAN_EXT} 1 -1 MAN_NUM)

    add_custom_command (
        OUTPUT ${HTML_OUT}
        COMMAND mandoc -T html -O toc,style=style.css,man=%N.%S.html
          ${MAN_IN} > ${HTML_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${MAN_IN}
        COMMENT "Generating HTML manual page ${MAN_BASE}.html")

    list(APPEND MANPAGES_HTML ${HTML_OUT})

    install(FILES ${MAN_IN}
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_NUM})
endforeach()

set(INDEX_SRC index.7)
set(INDEX_HTML "${CMAKE_CURRENT_BINARY_DIR}/index.html")

add_custom_command (
    OUTPUT  ${INDEX_HTML}
    COMMAND mandoc -T html -O toc,style=style.css,man=%N.%S.html
      ${INDEX_SRC} > ${INDEX_HTML}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${INDEX_SRC}
    COMMENT "Generating HTML manual page index.html")

add_custom_target (manpages ALL DEPENDS ${MANPAGES_OUT})
add_custom_target (manpages_html DEPENDS ${MANPAGES_HTML} ${INDEX_HTML})
