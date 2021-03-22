project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

include(FindPkgConfig)
include(GNUInstallDirs)
include(CMakePushCheckState)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)

macro(check_type_size_in type headers var)
  cmake_push_check_state()
  SET(CMAKE_EXTRA_INCLUDE_FILES ${headers})
  check_type_size(${type} ${var})
  cmake_push_check_state(RESET)
endmacro()


if(CMAKE_SYSTEM_NAME MATCHES ".*Linux")
  set(Sys_Plat_Linux TRUE)
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
  SetBoth(ECI_EVENT_DRIVER KQueue)
  set(Sys_Plat_DragonFlyBSD TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
  set(Sys_Plat_HPUX TRUE)
  # make _r functions available
  add_definitions(-D_REENTRANT=1)
elseif(APPLE)
  set(Sys_Plat_BSD TRUE)
endif()

# definitions

set(PACKAGE_NAME InitWare)
set(PACKAGE_VERSION 0.9alpha)
set(PACKAGE_STRING "${PACKAGE_NAME} version ${PACKAGE_VERSION}")

set(DISTRIBUTION ${CMAKE_SYSTEM})

# conf folders and filenames
set(pkglibdir ${CMAKE_INSTALL_PREFIX}/lib/InitWare)
set(pkglibexecdir ${CMAKE_INSTALL_FULL_LIBEXECDIR}/InitWare)
set(pkgsysconfdir ${CMAKE_INSTALL_FULL_SYSCONFDIR}/InitWare)

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

set(NOTIFY_SOCKET "/run/InitWare/notify")
# for SysD "@/org/freedesktop/systemd1/notify"

if(NOT Sys_Plat_Linux)
pkg_check_modules(EPoll REQUIRED IMPORTED_TARGET epoll-shim)
pkg_check_modules(INotify REQUIRED IMPORTED_TARGET libinotify)
set(EPoll_Compat_Libs PkgConfig::EPoll PkgConfig::INotify)
endif()
pkg_check_modules (DBus REQUIRED IMPORTED_TARGET dbus-1)

find_package (Threads REQUIRED)


check_include_file(asm/types.h Have_asm_types_h)
check_include_file(linux/netlink.h Have_linux_netlink_h)
check_include_file(linux/sched.h Have_linux_sched_h)
check_include_file(sys/capability.h Have_sys_capability_h)
check_include_file(sys/endian.h Have_sys_endian_h)
check_include_file(sys/prctl.h Have_sys_prctl_h)
check_include_file(sys/procctl.h Have_sys_procctl_h)
check_include_file(sys/statvfs.h Have_sys_statvfs_h)
check_include_file(sys/sysmacros.h Have_sys_sysmacros_h)
check_include_file(sys/vfs.h Have_sys_vfs_h)
check_include_file(alloca.h Have_alloca_h)
check_include_file(endian.h Have_endian_h)
check_include_file(malloc.h Have_malloc_h)
check_include_file(mntent.h Have_mntent_h)
check_include_file(mqueue.h Have_mqueue_h)

list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")

check_symbol_exists(environ "unistd.h" Have_environ)
check_symbol_exists(waitid "sys/wait.h" Have_waitid)
check_symbol_exists(posix_fallocate "fcntl.h" Have_posix_fallocate)
check_symbol_exists(get_current_dir_name "unistd.h" Have_get_current_dir_name)
check_symbol_exists(program_invocation_short_name "errno.h" Have_program_invocation_short_name)
check_type_size_in(__compar_fn_t "stdlib.h" Have___compar_fn_t)
check_function_exists(mempcpy Have_mempcpy)
check_function_exists(secure_getenv Have_secure_getenv)
check_function_exists(__secure_getenv Have___secure_getenv)

set(Use_capabilities FALSE CACHE BOOL "Use POSIX capabilities")

add_library(internal INTERFACE)
target_include_directories(internal INTERFACE common head head/systemd)

add_subdirectory(lib)
add_subdirectory(cmd)