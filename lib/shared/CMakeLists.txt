set(shared_src mkdir-label.c acpi-fpdt.c MurmurHash3.c
    ask-password-api.c pager.c boot-timestamps.c
    path-util.c calendarspec.c prioq.c
    ptyfwd.c ratelimit.c conf-files.c replace-var.c conf-parser.c
    set.c sleep-config.c device-nodes.c
    socket-util.c efivars.c spawn-ask-password-agent.c
    env-util.c spawn-polkit-agent.c exit-status.c fdset.c strbuf.c
    fileio.c strv.c strxcpyx.c hashmap.c time-dst.c
    time-util.c install.c unit-name.c install-printf.c utf8.c label.c util.c
    log.c
    virt.c mkdir.c)

if(Sys_Plat_Linux)
    list(APPEND shared_src linprocfs/proc-util.c)
elseif(Sys_Plat_BSD)
    list(APPEND shared_src kvm/proc-util.c)
    list(APPEND KVM_Libs kvm)
else()
    message(FATAL_ERROR "No process utilities for this platform - please port.")
endif()

set(shared_src_linux cgroup-show.c cgroup-util.c hwclock.c selinux-util.c
    watchdog.c utmp-wtmp.c)
set(shared_src_Use_Libcap capability.c)

add_library(initware-shared ${shared_src})
target_include_directories(initware-shared PUBLIC head)
target_link_libraries(initware-shared internal compat PkgConfig::DBus ${KVM_Libs})

# ------------------------------------------------------------------------------
add_library(initware-dbus dbus-common.c dbus-loop.c polkit.c)
target_include_directories(initware-dbus PUBLIC head)
target_link_libraries(initware-dbus internal compat PkgConfig::DBus)

# ------------------------------------------------------------------------------
add_library(initware-units install.c install-printf.c path-lookup.c specifier.c)
target_include_directories(initware-units PUBLIC head)
target_link_libraries(initware-units internal compat PkgConfig::DBus)

# ------------------------------------------------------------------------------
set(label_src socket-label.c mkdir-label.c ask-password-api.c
    fileio-label.c dev-setup.c)

set(label_src_linux selinux-util.c)

add_library(initware-label ${label_src})
target_include_directories(initware-label PUBLIC head)
target_link_libraries(initware-label internal compat PkgConfig::DBus)
#link also with selinux