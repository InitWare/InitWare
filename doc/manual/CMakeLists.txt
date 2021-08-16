
set(DOCBOOKS svc_job.7.xml unitfile.5.xml unitfile_automount.5.xml
    unitfile_mount.5.xml unitfile_service.5.xml unitfile_swap.5.xml
    unitfile_device.5.xml unitfile_path.5.xml unitfile_slice.5.xml
    unitfile_target.5.xml unitfile_exec.5.xml unitfile_rlimit.5.xml
    unitfile_snapshot.5.xml unitfile_timer.5.xml unitfile_kill.5.xml
    unitfile_scope.5.xml unitfile_socket.5.xml)

if (Python_FOUND)
	set(INDEX_XML "${CMAKE_CURRENT_BINARY_DIR}/index.7.xml")

	add_custom_command (OUTPUT  ${INDEX_XML}
	    COMMAND $<TARGET_FILE:Python::Interpreter>
		${PROJECT_SOURCE_DIR}/tools/make_man_index.py
		${INDEX_XML} ${DOCBOOKS}
	    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	    DEPENDS ${DOCBOOKS}
	    COMMENT "Generating manual page index index.7.xml")

	list(APPEND DOCBOOKS ${CMAKE_CURRENT_BINARY_DIR}/index.7.xml)
endif ()

foreach (DOCBOOK_IN ${DOCBOOKS})
	get_filename_component(MAN_BASE ${DOCBOOK_IN} NAME_WLE)
	set(MDOC_OUT ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE})
	set(HTML_OUT ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE}.html)

	add_custom_command(
	    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MAN_BASE}
	    COMMAND $<TARGET_FILE:iw-docbook2mdoc> ${DOCBOOK_IN}
		> ${MDOC_OUT}
	    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	    DEPENDS ${DOCBOOK_IN} $<TARGET_FILE:iw-docbook2mdoc>
	    COMMENT "Generating MDoc manual page ${MAN_BASE}")

	add_custom_command (
	    OUTPUT ${HTML_OUT}
	    COMMAND xsltproc --xinclude -o ${HTML_OUT} webman.xsl ${DOCBOOK_IN}
	    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	    DEPENDS ${DOCBOOK_IN} webman.xsl
	    COMMENT "Generating HTML manual page ${MAN_BASE}.html")

	list(APPEND MANPAGES_HTML ${HTML_OUT})
	list(APPEND MDOCS ${MDOC_OUT})
endforeach ()

foreach (MAN_IN ${MDOCS})
	get_filename_component(MAN_EXT ${MAN_IN} LAST_EXT)
	string(SUBSTRING ${MAN_EXT} 1 -1 MAN_NUM)

	install(FILES ${MAN_IN}
	    DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_NUM})
endforeach ()

add_custom_target(manpages ALL DEPENDS ${MDOCS})
add_custom_target(manpages_html DEPENDS ${MANPAGES_HTML})
