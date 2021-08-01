#
# Some notes on style:
# - Variables are named in Snake_CamelCase. In some cases (e.g. variables whose
#   names refer to actually existing filenames) the casing may vary.
#   Some kinds of variable get a type prefix. These follow below:
#   - AbsPath[Bin]: absolute path [to a binary]
#   - AbsDir: Absolute path to a directory.
#   - RelPath[Bin]: relative path [to a binary]
#   - RelDir: Relative path to a directory.
#     Use:     optional feature usage (on/off)
#     Kind:    configurable feature kind
#     Have:    whether a library, header, or similar is present.
#
#   The purpose of using Snake_CamelCase is to clearly distinguish these
#   build system-generated settings from everything else in the source tree, by
#   using a style unused anywhere else. The type prefixes offer clarification
#   that literal type does not.

project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE -D__BSD_VISIBLE")

macro(check_type_size_in type headers var)
  cmake_push_check_state()
  # why must I do it twice, CMake?! I never asked to clear it in the first
  # place!!
  list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE -D__BSD_VISIBLE")
  set(CMAKE_EXTRA_INCLUDE_FILES ${headers})
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
#-------------------------------------------------------------------------------

# These are default values for some options, but they'll be changed if
# appropriate libraries or features are discovered during configuration.

set(Default_Use_CGroups OFF)
set(Default_Linux "none")
set(Default_AbsDir_RunState "/var/run")
set(Default_Kind_Automount "none")
set(Default_Kind_Mount "none")
set(Default_Kind_Swap "none")

if(CMAKE_SYSTEM_NAME MATCHES ".*Linux")
  set(Sys_Plat_Linux TRUE)
  set(Default_Use_CGroups ON)
  set(Default_Kind_Automount "linux")
  set(Default_Kind_Mount "linux")
  set(Default_Kind_Swap "linux")
  set(Default_AbsDir_RunState "/run")
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

if(Sys_Plat_BSD)
  set(Default_Use_KQProc YES)
else()
  set(Default_Use_KQProc NO)
endif()

if(NOT Sys_Plat_Linux)
pkg_check_modules(INotify REQUIRED IMPORTED_TARGET libinotify)
set(EPoll_Compat_Libs PkgConfig::INotify)
endif()
pkg_check_modules(UDev IMPORTED_TARGET libudev)
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
check_include_file(sys/ucred.h Have_sys_ucred_h)
check_include_file(sys/vfs.h Have_sys_vfs_h)
check_include_file(alloca.h Have_alloca_h)
check_include_file(endian.h Have_endian_h)
check_include_file(malloc.h Have_malloc_h)
check_include_file(mntent.h Have_mntent_h)
check_include_file(mqueue.h Have_mqueue_h)
check_include_file(printf.h Have_printf_h)
check_include_file(xlocale.h Have_xlocale_h)

check_library_exists(pam pam_start "" Have_PAM)
check_library_exists(devattr udev_new "" Have_udev_as_devattr)
check_library_exists(rt mq_open "" Have_mq_open_in_rt)
check_function_exists(mq_open Have_mq_open)
check_symbol_exists(environ "unistd.h" Have_environ)
check_symbol_exists(get_current_dir_name "unistd.h" Have_get_current_dir_name)
check_symbol_exists(gettid "unistd.h" Have_gettid)
check_function_exists(mempcpy Have_mempcpy)
check_symbol_exists(posix_fallocate "fcntl.h" Have_posix_fallocate)
check_symbol_exists(program_invocation_short_name "errno.h" Have_program_invocation_short_name)
check_function_exists(secure_getenv Have_secure_getenv)
check_function_exists(__secure_getenv Have___secure_getenv)
check_symbol_exists(strtonum "stdlib.h" Have_strtonum)

check_type_size_in(__compar_fn_t "stdlib.h" Have___compar_fn_t)
check_type_size_in("struct cmsgcred" "sys/socket.h" Have_struct_cmsgcred)
check_type_size_in("struct statfs" "sys/statfs.h;sys/statvfs.h" Have_statfs)
check_type_size_in("struct statvfs" "sys/statvfs.h" Have_statvfs)
check_type_size_in("struct ucred" "sys/socket.h" Have_socket_struct_ucred)

check_symbol_exists(waitid "sys/wait.h" Have_waitid)
check_symbol_exists(parse_printf_format "printf.h" Have_parse_printf_format)

if(Have_mq_open_in_rt)
  set(Have_mq_open TRUE)
endif()

#-------------------------------------------------------------------------------
# options configurable by the user
#-------------------------------------------------------------------------------

# Use flags: these enable or disable features
option(Use_SystemdDBus "Systemd-compatible D-Bus interface" ON)
option(Use_SystemdCompat
  "Systemd-compatible paths and behaviour (Linux-only)"
  OFF)

option(HAVE_SPLIT_USR
  "Don't have a jumbled-together /usr and /"
  ON)
option(Use_CGroups
  "Use GNU/Linux Control Groups for advanced process tracking"
  ${Default_Use_CGroups})
option(Use_KQProc
  "Use Kernel Queues for advanced process tracking"
  ${Default_Use_KQProc})
option(Use_Libcap "Use POSIX capabilities (libcap)" ${Cap_FOUND})
option(Use_Libdevattr "Use udev (libdevattr)" ${Have_udev_as_devattr})
option(Use_Libudev "Use udev (libudev)" ${UDev_FOUND})
option(Use_MQueue "Use POSIX message queues" ${Have_mq_open})
option(Use_PAM "Use PAM authentication" ${Have_PAM})

if(${Use_SystemdCompat})
set(PkgDirName "systemd")
else()
set(PkgDirName "InitWare")
endif()

# Paths, either absolute ("full") or relative ("rel")
set(AbsDir_RunState "${Default_AbsDir_RunState}"
  CACHE STRING
  "Full path to the system runtime state directory, e.g. /var/run")

set(AbsDir_PkgRunState "${AbsDir_RunState}/${PkgDirName}"
  CACHE STRING
  "Full path to the directory in which to store the run-time state of InitWare,
e.g. /var/run/InitWare")

set(AbsDir_User_RunStateBase "${AbsDir_RunState}/user"
  CACHE STRING
  "Full path to the directory in which to generate subdirectories for runtime
state of each logged-in user, e.g. /var/run/user")

set(RelDir_PkgLib "lib/${PkgDirName}" CACHE STRING
"Relative to the install prefix, the directory for storing \
system-provided, read-only InitWare configuration and unit0files. ")

set(RelDir_PkgLibExec "${CMAKE_INSTALL_LIBEXECDIR}/${PkgDirName}"
  CACHE STRING
  "Relative to the install prefix, the directory for storing executables not \
intended for running by the user, e.g. agents and generators.")

set(RelDir_PkgSysConf "${CMAKE_INSTALL_SYSCONFDIR}/${PkgDirName}"
  CACHE STRING
  "Relative to the install prefix, the directory for storing  \
node-specific, administrator-modifiable configuration and unit-files.")

if(Use_Libdevattr OR Use_Libudev)
  set(Default_Kind_Device "udev")
else()
  set(Default_Kind_Device "none")
endif()

set(Kind_Device ${Default_Kind_Device} CACHE STRING
  "Kind of .device unit to provide, or none")
set_property(CACHE Kind_Device PROPERTY STRINGS none udev)

set(Kind_Mount ${Default_Kind_Mount} CACHE STRING
  "Kind of mount unit to provide, or none")
set_property(CACHE Kind_Mount PROPERTY STRINGS none linux)

set(Kind_Automount ${Default_Kind_Automount} CACHE STRING
  "Kind of .automount unit to provide, or none")
set_property(CACHE Kind_Automount PROPERTY STRINGS none linux)

set(Kind_Swap ${Default_Kind_Swap} CACHE STRING
  "Kind of .swap unit to provide, or none")
set_property(CACHE Kind_Swap PROPERTY STRINGS none linux)

# computed libraries/settings

if(${Use_Libdevattr})
  set(UDev_Libs devattr prop)
elseif(${Use_Libudev})
  set(UDev_Libs PkgConfig::UDev)
endif()

if(Have_mq_open_in_rt AND ${Use_MQueue})
  set(MQ_Libs rt)
endif()

if(${Use_Libcap})
  set(Cap_Libs PkgConfig::Cap)
endif()

#-------------------------------------------------------------------------------
# computed paths
#-------------------------------------------------------------------------------

# systemdstatedir
set(AbsDir_InitWareStateDir ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${PkgDirName})
set(AbsDir_PkgLib ${CMAKE_INSTALL_PREFIX}/${RelDir_PkgLib})
set(AbsDir_PkgLibExec ${CMAKE_INSTALL_PREFIX}/${RelDir_PkgLibExec})
set(AbsDir_PkgSysConf ${CMAKE_INSTALL_PREFIX}/${RelDir_PkgSysConf})

set(RelDir_UserUnitfiles ${RelDir_PkgLib}/user)
set(userunitdir ${AbsDir_PkgLib}/user)
set(usergeneratordir ${AbsDir_PkgLibExec}/user-generators)

set(RelDir_SystemUnitfiles ${RelDir_PkgLib}/system)
set(systemunitdir ${AbsDir_PkgLib}/system)
set(systemgeneratordir ${AbsDir_PkgLibExec}/system-generators)

set(SYSTEM_CONFIG_UNIT_PATH ${AbsDir_PkgSysConf}/system)
set(SYSTEM_DATA_UNIT_PATH ${systemunitdir})
set(SYSTEM_GENERATOR_PATH ${systemgeneratordir})

set(USER_CONFIG_UNIT_PATH ${AbsDir_PkgSysConf}/user)
set(USER_DATA_UNIT_PATH ${userunitdir})
set(USER_GENERATOR_PATH ${usergeneratordir})

# data paths
set(AbsPath_CatalogDatabase ${AbsDir_InitWareStateDir}/catalog/database)

# binary paths
set(SYSTEMCTL_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/iwctl)
set(SYSTEMD_BINARY_PATH ${AbsDir_PkgLibExec}/iw.manager)
set(SYSTEMD_CGROUP_AGENT_AGENT ${AbsDir_PkgLibExec}/iw.cgroups-agent)
set(SYSTEMD_SHUTDOWN_BINARY_PATH ${AbsDir_PkgLibExec}/iw.shutdown)
set(SYSTEMD_SLEEP_BINARY_PATH ${AbsDir_PkgLibExec}/iw.sleep)
set(SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH
  ${AbsDir_PkgLibExec}/iw.tty-ask-password-agent)
set(SYSTEMD_STDIO_BRIDGE_BINARY_PATH
  ${AbsDir_PkgLibExec}/iw.stdio-bridge)
#todo: find
set(POLKIT_AGENT_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/pkttyagent)

set(BinPath_Runrcng ${AbsDir_PkgLibExec}/runrcng.sh)

#-------------------------------------------------------------------------------
# actual building commands
#-------------------------------------------------------------------------------

add_library(internal INTERFACE)
target_include_directories(internal INTERFACE common head head/systemd)

add_subdirectory(vendor/iw-cjson)
add_subdirectory(vendor/iw-libev)

# if (build_doc) or something like that
add_subdirectory(vendor/iw-docbook2mdoc)
add_subdirectory(doc/manual)
# endif

add_subdirectory(lib)
add_subdirectory(cmd)
add_subdirectory(share)

configure_file(lib/compat/head/compat.h.in lib/compat/head/compat.h)

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

message("Feature settings (Use flags):")
FShow("Systemd-compatible D-Bus interface" Use_SystemdDBus)
FShow("Systemd-compatible paths & behaviour" Use_SystemdCompat)
FShow("Non-combined /usr and /" HAVE_SPLIT_USR)

message("  Advanced process tracking:")
FShow("    -> GNU/Linux Control Groups (CGroups)" Use_CGroups)
FShow("    -> Kernel Queues PROC event filter" Use_KQProc)

message("  Authentication module:")
FShow("    -> Pluggable AUthentication Modules (PAM)" Use_PAM)

FShow("POSIX Capabilities (libcap)" Use_Libcap)
FShow("POSIX Message Queues" Use_MQueue)
FShow("UDev (libdevattr)" Use_Libdevattr)
FShow("UDev (libudev)" Use_Libudev)

message("Optional units:")
FShow(".device" Kind_Device)
FShow(".mount" Kind_Mount)
FShow(".automount" Kind_Automount)
FShow(".swap" Kind_Swap)

message("Paths:")
FShow("Prefix" CMAKE_INSTALL_PREFIX)
FShow("  -> InitWare-internal executables" AbsDir_PkgLibExec)
FShow("  -> System-provided InitWare data" AbsDir_PkgLib)
FShow("  -> Node-specific InitWare data" AbsDir_PkgSysConf)
FShow("System runtime state" AbsDir_RunState)
FShow("User runtime state base" AbsDir_User_RunStateBase)
FShow("InitWare runtime state" AbsDir_PkgRunState)

# finally, add relevant options to the M4 macro definitions
foreach(option Sys_Plat_Linux Sys_Plat_BSD Sys_Plat_DragonFlyBSD
  Sys_Plat_FreeBSD Sys_Plat_NetBSD Sys_Plat_OpenBSD)
if(${option})
  list(APPEND M4_Defs "-D${OPTION}=${${option}}")
endif()
endforeach()
