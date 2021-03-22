set(shared_src acl-util.c mkdir-label.c acpi-fpdt.c MurmurHash3.c
    ask-password-api.c pager.c audit.c path-lookup.c boot-timestamps.c
    path-util.c calendarspec.c polkit.c capability.c prioq.c
    ptyfwd.c ratelimit.c conf-files.c replace-var.c conf-parser.c
    selinux-util.c dbus-common.c set.c dbus-loop.c sleep-config.c device-nodes.c
    socket-label.c dev-setup.c socket-util.c efivars.c spawn-ask-password-agent.c
    env-util.c spawn-polkit-agent.c exit-status.c specifier.c fdset.c strbuf.c
    fileio.c strv.c fileio-label.c strxcpyx.c hashmap.c time-dst.c hwclock.c
    time-util.c install.c unit-name.c install-printf.c utf8.c label.c util.c
    log.c utmp-wtmp.c logs-show.c virt.c mkdir.c)

set(shared_src_linux cgroup-show.c cgroup-util.c selinux-util.c watchdog.c)

add_library(initware-shared ${shared_src})
target_include_directories(initware-shared PUBLIC head)
target_link_libraries(initware-shared internal compat)

