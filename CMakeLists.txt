project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

include(FindPkgConfig)
include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)


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

if(NOT Sys_Plat_Linux)
pkg_check_modules(EPoll REQUIRED IMPORTED_TARGET epoll-shim)
pkg_check_modules(INotify REQUIRED IMPORTED_TARGET libinotify)
set(EPoll_Compat_Libs PkgConfig::EPoll PkgConfig::INotify)
endif()
pkg_check_modules (DBus REQUIRED IMPORTED_TARGET dbus-1)

check_include_file(sys/endian.h Have_sys_endian_h)
check_include_file(sys/sysmacros.h Have_sys_sysmacros_h)
check_include_file(endian.h Have_endian_h)
check_include_file(malloc.h Have_malloc_h)
check_include_file(mqueue.h Have_mqueue_h)

check_symbol_exists(waitid "sys/wait.h" HAVE_waitid)
check_symbol_exists(posix_fallocate "fcntl.h" HAVE_posix_fallocate)
check_function_exists(mempcpy Have_mempcpy)
check_function_exists(secure_getenv Have_secure_getenv)
check_function_exists(__secure_getenv Have___secure_getenv)

add_library(internal INTERFACE)
target_include_directories(internal INTERFACE head/systemd)

add_subdirectory(lib)