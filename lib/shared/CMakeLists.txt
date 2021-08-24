set(shared_src mkdir-label.c acpi-fpdt.c MurmurHash3.c
    ask-password-api.c pager.c boot-timestamps.c
    path-util.c calendarspec.c prioq.c
    ptyfwd.c ratelimit.c conf-files.c replace-var.c conf-parser.c
    set.c sleep-config.c device-nodes.c
    socket-util.c efivars.c spawn-ask-password-agent.c
    env-util.c spawn-polkit-agent.c exit-status.c fdset.c strbuf.c
    fileio.c strv.c strxcpyx.c hashmap.c time-dst.c
    time-util.c install.c unit-name.c install-printf.c utf8.c label.c util.c
    log.c cjson-util.c virt.c mkdir.c)

if(Use_CGroups)
	list(APPEND shared_src cgroup-show.c cgroup-util.c)
endif()

if (Sys_Plat_Linux)
	list(APPEND shared_src linprocfs/fdset.c linprocfs/proc-util.c
	    cgroup-show.c cgroup-util.c hwclock.c selinux-util.c watchdog.c
	    utmp-wtmp.c)
elseif (Sys_Plat_MacOS)
	list(APPEND shared_src macos/proc-util.c ptgroup-show.c)
elseif (Sys_Plat_BSD)
	list(APPEND shared_src kvm/fdset.c kvm/proc-util.c ptgroup-show.c)
	list(APPEND KVM_Libs kvm)
else ()
	message(FATAL_ERROR "No process utilities for this platform - please port.")
endif ()

if(Sys_Plat_FreeBSD)
	list(APPEND KVM_Libs util)
endif()

if(Use_Libcap)
	list(APPEND shared_src capability.c)
endif()

add_library(iw-shared ${shared_src})
target_include_directories(iw-shared PUBLIC head)
target_link_libraries(iw-shared internal compat iw-cjson iw-ev
    PkgConfig::DBus ${KVM_Libs} ${Cap_Libs})

# ------------------------------------------------------------------------------
add_library(iw-dbus dbus-common.c polkit.c dbus-loop-libev.c)
target_include_directories(iw-dbus PUBLIC head)
target_link_libraries(iw-dbus internal compat iw-ev PkgConfig::DBus)

# ------------------------------------------------------------------------------
add_library(iw-units install.c install-printf.c path-lookup.c specifier.c)
target_include_directories(iw-units PUBLIC head)
target_link_libraries(iw-units internal compat iw-ev PkgConfig::DBus)

# ------------------------------------------------------------------------------
set(label_src socket-label.c mkdir-label.c ask-password-api.c fileio-label.c
    dev-setup.c)

set(label_src_linux selinux-util.c)

add_library(iw-label ${label_src})
target_include_directories(iw-label PUBLIC head)
target_link_libraries(iw-label internal compat iw-ev PkgConfig::DBus)
# TODO: link also with selinux