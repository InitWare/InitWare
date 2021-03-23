project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

# basic definitions

set(PACKAGE_NAME InitWare)
set(PACKAGE_VERSION 0.9alpha)
set(PACKAGE_STRING "${PACKAGE_NAME} version ${PACKAGE_VERSION}")

set(DISTRIBUTION ${CMAKE_SYSTEM})

include(FindPkgConfig)
include(GNUInstallDirs)
include(CMakeDependentOption)
include(CMakePushCheckState)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

macro(check_type_size_in type headers var)
  cmake_push_check_state()
  SET(CMAKE_EXTRA_INCLUDE_FILES ${headers})
  check_type_size(${type} ${var})
  cmake_push_check_state(RESET)
endmacro()

# If ${var} is set to anything, set ${var2} to true
macro(set_to_true var var2)
  if (${var})
    message("${var} is true")
    set(${var2} TRUE)
  endif()
endmacro()

#-------------------------------------------------------------------------------
# feature checks

# These are default values for some options, but they'll be changed if
# appropriate libraries or features are discovered during configuration.

# Default value for options with either a "none" or a "linux" option
set(default_linux "none")
set(Default_Runstatedir "/var/run")

if(CMAKE_SYSTEM_NAME MATCHES ".*Linux")
  set(Sys_Plat_Linux TRUE)
  set(default_linux "linux")
  set(Default_Runstatedir "/run")
  add_definitions("-D_GNU_SOURCE")
elseif(CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
  set(Sys_Plat_BSD TRUE)
  set(Sys_Plat_FreeBSD TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "kNetBSD.*|NetBSD.*")
  set(Sys_Plat_BSD TRUE)
  set(Sys_Plat_NetBSD TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
  set(Sys_Plat_BSD TRUE)
  set(Sys_Plat_OpenBSD TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
  set(Sys_Plat_BSD TRUE)
  set(Sys_Plat_DragonFlyBSD TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
  set(Sys_Plat_HPUX TRUE)
  # make _r functions available
  add_definitions(-D_REENTRANT=1)
elseif(APPLE)
  set(Sys_Plat_BSD TRUE)
endif()

if(NOT Sys_Plat_Linux)
pkg_check_modules(EPoll REQUIRED IMPORTED_TARGET epoll-shim)
pkg_check_modules(INotify REQUIRED IMPORTED_TARGET libinotify)
set(EPoll_Compat_Libs PkgConfig::EPoll PkgConfig::INotify)
endif()
pkg_check_modules(UDev IMPORTED_TARGET udev)
pkg_check_modules(Cap IMPORTED_TARGET libcap)
pkg_check_modules(DBus REQUIRED IMPORTED_TARGET dbus-1)

find_package (Threads REQUIRED)

check_include_file(asm/types.h Have_asm_types_h)
check_include_file(linux/netlink.h Have_linux_netlink_h)
check_include_file(linux/sched.h Have_linux_sched_h)
check_include_file(sys/capability.h Have_sys_capability_h)
check_include_file(sys/endian.h Have_sys_endian_h)
check_include_file(sys/prctl.h Have_sys_prctl_h)
check_include_file(sys/procctl.h Have_sys_procctl_h)
check_include_file(sys/statfs.h Have_sys_statfs_h)
check_include_file(sys/statvfs.h Have_sys_statvfs_h)
check_include_file(sys/sysmacros.h Have_sys_sysmacros_h)
check_include_file(sys/vfs.h Have_sys_vfs_h)
check_include_file(alloca.h Have_alloca_h)
check_include_file(endian.h Have_endian_h)
check_include_file(malloc.h Have_malloc_h)
check_include_file(mntent.h Have_mntent_h)
check_include_file(mqueue.h Have_mqueue_h)

list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")

check_library_exists(devattr udev_new "" Have_udev_as_devattr)
check_library_exists(rt mq_open "" Have_mq_open_in_rt)
check_function_exists(mq_open Have_mq_open)
check_symbol_exists(environ "unistd.h" Have_environ)
check_symbol_exists(waitid "sys/wait.h" Have_waitid)
check_symbol_exists(posix_fallocate "fcntl.h" Have_posix_fallocate)
check_symbol_exists(get_current_dir_name "unistd.h" Have_get_current_dir_name)
check_symbol_exists(program_invocation_short_name "errno.h" Have_program_invocation_short_name)
check_type_size_in(__compar_fn_t "stdlib.h" Have___compar_fn_t)
check_function_exists(mempcpy Have_mempcpy)
check_function_exists(secure_getenv Have_secure_getenv)
check_function_exists(__secure_getenv Have___secure_getenv)
check_type_size_in("struct statfs" "sys/statfs.h;sys/statvfs.h" Have_statfs)
check_type_size_in("struct statvfs" "sys/statvfs.h" Have_statvfs)

if(DEFINED Have_mq_open_in_rt)
  set(Have_mq_open TRUE)
endif()

if(DEFINED UDev_FOUND OR DEFINED Have_udev_as_devattr)
  set(Default_Device "udev")
else()
  set(Default_Device "none")
endif()

#-------------------------------------------------------------------------------
# options configurable by the user
#-------------------------------------------------------------------------------

option(Use_SystemdDBus "Systemd-compatible D-Bus interface" OFF)
option(Use_SystemdCompat "Systemd-compatible paths and behaviour (Linux-only)" OFF)
option(Use_Cap "Use POSIX capabilities from LibCap" ${Cap_FOUND})
option(Use_MQueue "Use POSIX message queues" ${Have_mq_open})
option(Use_UDev "Use UDev (libudev)" ${UDev_FOUND})
option(Use_Devattr "Use UDev (libdevattr)" ${Have_udev_as_devattr})

if(${Use_SystemdCompat})
set(Default_NOTIFY_SOCKET "@/org/freedesktop/systemd1/notify")
set(pkgdirname "systemd")
else()
set(Default_NOTIFY_SOCKET "/run/InitWare/notify")
set(pkgdirname "InitWare")
endif()

set(Relative_Pkglibdir "lib/${pkgdirname}" CACHE STRING
"Relative to the install prefix, the directory for storing \
system-provided unit-files and configuration. ")

set(Relative_Pkglibexecdir "${CMAKE_INSTALL_LIBEXECDIR}/${pkgdirname}"
  CACHE STRING
  "Relative to the install prefix, the directory for storing executables not \
intended for running by the user, e.g. agents and generators.")

set(Relative_Pkgsysconfdir "${CMAKE_INSTALL_SYSCONFDIR}/${pkgdirname}"
  CACHE STRING
  "Relative to the install prefix, the directory for storing  \
node-specific, administrator-modifiable configuration and unit-files.")

set(Full_Runstatedir "${Default_Runstatedir}"
  CACHE STRING
  "Full path to the directory used by the system to store global run-time \
variable data.")

set(NOTIFY_SOCKET ${Default_NOTIFY_SOCKET} CACHE STRING
  "Path to the notification socket that will be created by InitWare")

set(Kind_Device ${Default_Device} CACHE STRING
  "Kind of .device unit to provide, or none")
set_property(CACHE Kind_Device PROPERTY STRINGS none udev)

set(Kind_Mount ${default_linux} CACHE STRING
  "Kind of mount unit to provide, or none")
set_property(CACHE Kind_Mount PROPERTY STRINGS none linux)

set(Kind_Automount ${default_linux} CACHE STRING
  "Kind of .automount unit to provide, or none")
set_property(CACHE Kind_Automount PROPERTY STRINGS none linux)

set(Kind_Swap ${default_linux} CACHE STRING
  "Kind of .swap unit to provide, or none")
set_property(CACHE Kind_Swap PROPERTY STRINGS none linux)

# computed libraries/settings

if(${Use_Devattr})
  set(UDev_Libs devattr prop)
elseif(${Use_UDev})
  set(UDev_Libs PkgConfig::UDev)
endif()

if(DEFINED Have_mq_open_in_rt AND ${Use_MQueue})
  set(MQ_Libs rt)
endif()

if(${Use_Libcap})
  set(Cap_Libs PkgConfig::Cap)
endif()

#-------------------------------------------------------------------------------
# computed paths
#-------------------------------------------------------------------------------

set(pkglibdir ${CMAKE_INSTALL_PREFIX}/${Relative_Pkglibdir})
set(pkglibexecdir ${CMAKE_INSTALL_PREFIX}/${Relative_Pkglibexecdir})
set(pkgsysconfdir ${CMAKE_INSTALL_PREFIX}/${Relative_Pkgsysconfdir})
set(runstatedir ${Full_Runstatedir})
set(pkgrunstatedir ${Full_Runstatedir}/${pkgdirname})

set(userunitdir ${pkglibdir}/user)
set(usergeneratordir ${pkglibexecdir}/user-generators)

set(systemunitdir ${pkglibdir}/system)
set(systemgeneratordir ${pkglibexecdir}/system-generators)

set(SYSTEM_CONFIG_UNIT_PATH ${pkgsysconfdir}/system)
set(SYSTEM_DATA_UNIT_PATH ${systemunitdir})
set(SYSTEM_GENERATOR_PATH ${systemgeneratordir})

set(USER_CONFIG_UNIT_PATH ${pkgsysconfdir}/user)
set(USER_DATA_UNIT_PATH ${userunitdir})
set(USER_GENERATOR_PATH ${usergeneratordir})

# binary paths
set(SYSTEMCTL_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/iwctl)
set(SYSTEMD_BINARY_PATH ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.manager)
set(SYSTEMD_CGROUP_AGENT_AGENT ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.cgroups-agent)
set(SYSTEMD_SHUTDOWN_BINARY_PATH ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.shutdown)
set(SYSTEMD_SLEEP_BINARY_PATH ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.sleep)
set(SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH
  ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.tty-ask-password-agent)
set(SYSTEMD_STDIO_BRIDGE_BINARY_PATH
  ${CMAKE_INSTALL_FULL_LIBEXECDIR}/iw.stdio-bridge)
#todo: find
set(POLKIT_AGENT_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/pkttyagent)

#-------------------------------------------------------------------------------
# actual building commands
#-------------------------------------------------------------------------------

add_library(internal INTERFACE)
target_include_directories(internal INTERFACE common head head/systemd)

add_subdirectory(lib)
add_subdirectory(cmd)

#-------------------------------------------------------------------------------
# display enabled options
#-------------------------------------------------------------------------------

function(FShow name flag)
    if(${flag})
        message("  ${name}: ${${flag}}")
    else()
        message("  ${name}: OFF")
    endif()
endfunction(FShow)

message("Feature settings:")
FShow("Systemd-compatible D-Bus interface" Use_SystemdDBus)
FShow("Systemd-compatible paths & behaviour" Use_SystemdCompat)
FShow("LibCap POSIX Capabilities" Use_Libcap)
FShow("POSIX Message Queues" Use_MQueue)
FShow("U-Dev (LibUDev)" Use_UDev)
FShow("U-Dev (LibDevAttr)" Use_Devattr)

message("Unit types:")
FShow(".device" Kind_Device)
FShow(".mount" Kind_Mount)
FShow(".automount" Kind_Automount)
FShow(".swap" Kind_Swap)

message("Paths:")
FShow("Notify socket" NOTIFY_SOCKET)
FShow("Prefix" CMAKE_INSTALL_PREFIX)
FShow("InitWare-internal executables" pkglibexecdir)
FShow("System-provided InitWare data" pkglibdir)
FShow("Node-specific InitWare data" pkgsysconfdir)
FShow("Run-time state" runstatedir)
message("    InitWare-specific data will be in ${pkgrunstatedir}")
message("    'user' subdirectory will be ${runstatedir}/user")