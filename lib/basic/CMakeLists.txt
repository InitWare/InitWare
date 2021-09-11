add_library(initware-basic hashmap.c mempool.c MurmurHash2.c prioq.c siphash24.c
    strbuf.c strv.c acpi-fpdt.c apparmor-util.c async.c audit.c bus-label.c calendarspec.c condition.c conf-files.c conf-parser.c
    copy.c device-nodes.c dropin.c efivars.c env-util.c exit-status.c fdset.c
    fileio-label.c fileio.c fstab-util.c generator.c gunicode.c
    ima-util.c import-util.c in-addr-util.c install-printf.c install.c
    json.c label.c locale-util.c log.c login-shared.c logs-show.c
    mkdir-label.c mkdir.c pager.c path-lookup.c path-util.c 
    pty.c ratelimit.c replace-var.c ring.c selinux-util.c sigbus.c
    sleep-config.c smack-util.c socket-label.c socket-util.c
    spawn-ask-password-agent.c spawn-polkit-agent.c specifier.c
    strxcpyx.c time-dst.c time-util.c uid-range.c unit-name.c utf8.c util.c
    verbs.c virt.c xml.c cgroup-show.c cgroup-util.c watchdog.c)
target_include_directories(initware-basic
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/cmd/journal>)
target_link_libraries(initware-basic ${EPOLL_LIBS} bsdcompat)