foreach(tmpfile_in systemd.conf.in)
	get_filename_component(tmpfile_out ${tmpfile_in} NAME_WLE)
	configure_file(${tmpfile_in} ${tmpfile_out} @ONLY)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${tmpfile_out}
	    DESTINATION ${INSTALL_PKGLIB_DIR}/tmpfiles.d)
endforeach()