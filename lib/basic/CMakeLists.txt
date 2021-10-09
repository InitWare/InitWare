function (GenerateList name)
	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt
	COMMAND ${PROJECT_SOURCE_DIR}/tools/generate-${name}-list.sh ${CMAKE_C_COMPILER}
	    > ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt)

	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.gperf
	COMMAND ${PROJECT_SOURCE_DIR}/tools/generate-gperfs.sh ${name} ${name}_
	    < ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt
	    > ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.gperf
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt)

	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.h
	COMMAND gperf -L ANSI-C -t --ignore-case -N lookup_${name} -H hash_${name}
		-p < ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.gperf
		> ${name}-from-name.h
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.gperf)

	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${name}-to-name.h
	COMMAND awk -f ${CMAKE_CURRENT_SOURCE_DIR}/${name}-to-name.awk
	    < ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt
	    > ${name}-to-name.h
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${name}-list.txt)

	list(APPEND BASIC_SRC ${CMAKE_CURRENT_BINARY_DIR}/${name}-to-name.h
	    ${CMAKE_CURRENT_BINARY_DIR}/${name}-from-name.h)
	set(BASIC_SRC ${BASIC_SRC} PARENT_SCOPE)
endfunction (GenerateList)

if (SVC_PLATFORM_Linux)
	list(APPEND BASIC_SRC ptyfwd.c)
	list(APPEND BASIC_SRC procfs/fd.c procfs/proc.c)
elseif (SVC_PLATFORM_MacOS)
	# no KVM in macOS
	list(APPEND BASIC_SRC macos/proc.c)
elseif (SVC_PLATFORM_BSD)
	list(APPEND BASIC_SRC kvm/fd.c kvm/proc.c)
	list(APPEND BASIC_LIBS kvm)
else ()
	warning("No process utilities for this platform")
endif ()

if (SVC_PLATFORM_FreeBSD)
	list(APPEND BASIC_LIBS util) # for kinfo_getfile
endif ()

GenerateList(errno)
if (SVC_USE_libcap)
	GenerateList(cap)
	list(APPEND BASIC_SRC cap-list.c)
endif ()

list(APPEND BASIC_SRC MurmurHash2.c acpi-fpdt.c apparmor-util.c async.c audit.c
    base-filesystem.c bus-label.c calendarspec.c cgroup-util.c clock-util.c
    condition.c conf-files.c conf-parser.c copy.c dev-setup.c device-nodes.c
    dropin.c efivars.c env-util.c errno-list.c exit-status.c fdset.c
    fileio-label.c fileio.c fstab-util.c generator.c gunicode.c hashmap.c
    ima-util.c import-util.c in-addr-util.c install-printf.c install.c json.c
    label.c locale-util.c log.c login-shared.c mempool.c mkdir-label.c mkdir.c
    pager.c path-lookup.c path-util.c prioq.c ratelimit.c replace-var.c
    selinux-util.c sigbus.c siphash24.c sleep-config.c smack-util.c
    socket-label.c socket-util.c spawn-ask-password-agent.c spawn-polkit-agent.c
    specifier.c strbuf.c strv.c strxcpyx.c switch-root.c time-dst.c time-util.c
    uid-range.c unit-name.c utf8.c util.c verbs.c virt.c watchdog.c xml.c
    )

if (SVC_PLATFORM_Linux)
	list(APPEND BASIC_SRC memfd-util.c)
endif ()

if (${SVC_USE_libcap})
	list(APPEND BASIC_SRC capability.c)
	set(LIBCAP_LIBS PkgConfig::libcap)
endif ()

add_library(initware-basic ${BASIC_SRC})
target_include_directories(initware-basic
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/cmd/journal>)
target_link_libraries(initware-basic ${EPOLL_LIBS} ${LIBCAP_LIBS} ${BASIC_LIBS}
    bsdcompat Threads::Threads)