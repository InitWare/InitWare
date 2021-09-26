list(APPEND BASIC_SRC hashmap.c mempool.c MurmurHash2.c prioq.c siphash24.c
strbuf.c strv.c acpi-fpdt.c apparmor-util.c async.c audit.c base-filesystem.c bus-label.c calendarspec.c condition.c conf-files.c conf-parser.c
copy.c clock-util.c dev-setup.c device-nodes.c dropin.c efivars.c env-util.c exit-status.c fdset.c
fileio-label.c fileio.c fstab-util.c generator.c gunicode.c
ima-util.c import-util.c in-addr-util.c install-printf.c install.c
json.c label.c locale-util.c log.c login-shared.c
mkdir-label.c mkdir.c pager.c path-lookup.c path-util.c
ratelimit.c replace-var.c selinux-util.c sigbus.c
sleep-config.c smack-util.c socket-label.c socket-util.c
spawn-ask-password-agent.c spawn-polkit-agent.c specifier.c
strxcpyx.c switch-root.c time-dst.c time-util.c uid-range.c unit-name.c utf8.c util.c
verbs.c virt.c xml.c cgroup-util.c watchdog.c)

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
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/cmd/journal>)
target_link_libraries(initware-basic ${EPOLL_LIBS} ${LIBCAP_LIBS} bsdcompat
    Threads::Threads)