project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

macro (check_type_size_in type headers var)
	cmake_push_check_state()
	# why must I do it twice, CMake?! I never asked to clear it in the first
	# place!!
	list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE -D__BSD_VISIBLE")
	set(CMAKE_EXTRA_INCLUDE_FILES ${headers})
	check_type_size(${type} ${var})
	cmake_push_check_state(RESET)
endmacro ()

# If ${var} is set to anything, set ${var2} to true
macro (set_to_true var var2)
	if (${var})
		message("${var} is true")
		set(${var2} TRUE)
	endif ()
endmacro ()

# -------------------------------------------------------------------------------
# feature checks
# -------------------------------------------------------------------------------

# These are default values for some options, but they'll be changed if
# appropriate libraries or features are discovered during configuration.

set(Default_Use_CGroups OFF)
set(Default_Linux "none")
set(Default_INSTALL_RUNSTATE_DIR "/var/run")
set(Default_Kind_Automount "none")
set(Default_Kind_Mount "none")
set(Default_Kind_Swap "none")

if (CMAKE_SYSTEM_NAME MATCHES ".*Linux")
	set(Sys_Plat_Linux TRUE)
	set(Default_Use_CGroups ON)
	set(Default_Kind_Automount "linux")
	set(Default_Kind_Mount "linux")
	set(Default_Kind_Swap "linux")
	set(Default_INSTALL_RUNSTATE_DIR "/run")
	add_definitions("-D_GNU_SOURCE")
elseif (CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
	set(Sys_Plat_BSD TRUE)
	set(Sys_Plat_FreeBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "kNetBSD.*|NetBSD.*")
	set(Sys_Plat_BSD TRUE)
	set(Sys_Plat_NetBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
	set(Sys_Plat_BSD TRUE)
	set(Sys_Plat_OpenBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
	set(Sys_Plat_BSD TRUE)
	set(Sys_Plat_DragonFlyBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "HP-UX")
	set(Sys_Plat_HPUX TRUE)
	# make _r functions available
	add_definitions(-D_REENTRANT=1)
elseif (APPLE)
	set(Sys_Plat_BSD TRUE)
endif ()

if (Sys_Plat_BSD)
	set(Default_Use_KQProc YES)
else ()
	set(Default_Use_KQProc NO)
endif ()

if (NOT Sys_Plat_Linux)
	pkg_check_modules(INotify REQUIRED IMPORTED_TARGET libinotify)
	set(EPoll_Compat_Libs PkgConfig::INotify)
endif ()
pkg_check_modules(UDev IMPORTED_TARGET libudev)
pkg_check_modules(Cap IMPORTED_TARGET libcap)
pkg_check_modules(DBus REQUIRED IMPORTED_TARGET dbus-1)

find_package(Threads REQUIRED)
find_package(Python COMPONENTS Interpreter)

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
check_symbol_exists(program_invocation_short_name "errno.h"
		    Have_program_invocation_short_name)
check_function_exists(secure_getenv Have_secure_getenv)
check_function_exists(__secure_getenv Have___secure_getenv)
check_symbol_exists(strtod_l "stdlib.h" Have_stdlib_strtod_l)
check_symbol_exists(strtod_l "xlocale.h" Have_xlocale_strtod_l)
check_symbol_exists(strtonum "stdlib.h" Have_strtonum)

check_type_size_in(__compar_fn_t "stdlib.h" Have___compar_fn_t)
check_type_size_in("struct cmsgcred" "sys/socket.h" Have_struct_cmsgcred)
check_type_size_in("struct statfs" "sys/statfs.h;sys/statvfs.h" Have_statfs)
check_type_size_in("struct statvfs" "sys/statvfs.h" Have_statvfs)
check_type_size_in("struct ucred" "sys/socket.h" Have_socket_struct_ucred)

check_symbol_exists(waitid "sys/wait.h" Have_waitid)
check_symbol_exists(parse_printf_format "printf.h" Have_parse_printf_format)

if (Have_mq_open_in_rt)
	set(Have_mq_open TRUE)
endif ()

# -------------------------------------------------------------------------------
# options configurable by the user
# -------------------------------------------------------------------------------

# Use flags: these enable or disable features
option(Use_SystemdDBus "Systemd-compatible D-Bus interface" ON)
option(Use_SystemdCompat "Systemd-compatible paths and behaviour (Linux-only)"
    OFF)

option(HAVE_SPLIT_USR "Don't have a jumbled-together /usr and /" ON)
option(Use_CGroups "Use GNU/Linux Control Groups for advanced process tracking"
    ${Default_Use_CGroups})
option(Use_KQProc "Use Kernel Queues for advanced process tracking"
    ${Default_Use_KQProc})
option(Use_Libcap "Use POSIX capabilities (libcap)" ${Cap_FOUND})
option(Use_Libdevattr "Use udev (libdevattr)" ${Have_udev_as_devattr})
option(Use_Libudev "Use udev (libudev)" ${UDev_FOUND})
option(Use_MQueue "Use POSIX message queues" ${Have_mq_open})
option(Use_PAM "Use PAM authentication" ${Have_PAM})

if (${Use_SystemdCompat})
	set(PACKAGE_NAME systemd)
	set(PACKAGE_VERSION v208)
	set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
else ()
	set(PACKAGE_NAME InitWare)
	set(PACKAGE_VERSION 0.7alpha)
	set(PACKAGE_STRING "${PACKAGE_NAME} version ${PACKAGE_VERSION}")
endif ()

if (${Use_SystemdDBus})
	set(SCHEDULER_DBUS_BUSNAME "org.freedesktop.systemd1")
else ()
	set(SCHEDULER_DBUS_BUSNAME "org.InitWare.Scheduler1")
endif ()

# Paths, either absolute ("full") or relative ("rel")
set(INSTALL_RUNSTATE_DIR
    "${Default_INSTALL_RUNSTATE_DIR}"
    CACHE STRING
	"Full path to the system runtime state directory, e.g. /var/run")

set(INSTALL_PKGRUNSTATE_DIR
    "${INSTALL_RUNSTATE_DIR}/${PACKAGE_NAME}"
    CACHE STRING
	"Full path to the directory in which to store the run-time state of \
InitWare, e.g. /var/run/InitWare")

set(INSTALL_USERSTATE_DIR
    "${INSTALL_RUNSTATE_DIR}/user"
    CACHE STRING
	"Full path to the directory in which to generate subdirectories for runtime \
state of each logged-in user, e.g. /var/run/user")

set(INSTALL_PKGLIB_DIR
    "${CMAKE_INSTALL_PREFIX}/lib/${PACKAGE_NAME}"
    CACHE STRING
	"Full path to the directory for storing system-provided, read-only InitWare \
configuration and unit-files (not actual libraries). ")

set(INSTALL_PKGLIBEXEC_DIR
    "${CMAKE_INSTALL_FULL_LIBEXECDIR}/${PACKAGE_NAME}"
    CACHE STRING
	"Full path to the directory for storing executables not \
intended for running by the user, e.g. agents and generators.")

set(INSTALL_PKGSYSCONF_DIR
    "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PACKAGE_NAME}"
    CACHE STRING
	"Full path to the directory for storing  \
node-specific, administrator-modifiable configuration and unit-files.")

set(INSTALL_DBUSSERVICES_DIR
    "${CMAKE_INSTALL_FULL_DATAROOTDIR}/dbus-1/system-services"
    CACHE STRING
	"Full path to the directory for storing D-Bus system service files.")

set(INSTALL_DBUSCONF_DIR
    "${CMAKE_INSTALL_FULL_DATAROOTDIR}/dbus-1/system.d"
    CACHE STRING
	"Full path to the directory for storing D-Bus system service configuration."
)

set(INSTALL_POLKITACTION_DIR
    "${CMAKE_INSTALL_FULL_DATAROOTDIR}/polkit-1/actions"
    CACHE STRING
	"Full path to the directory for storing D-Bus system service configuration."
)

if (Use_Libdevattr OR Use_Libudev)
	set(Default_Kind_Device "udev")
else ()
	set(Default_Kind_Device "none")
endif ()

set(Kind_Device
    ${Default_Kind_Device}
    CACHE STRING "Kind of .device unit to provide, or none")
set_property(CACHE Kind_Device PROPERTY STRINGS none udev)

set(Kind_Mount
    ${Default_Kind_Mount}
    CACHE STRING "Kind of mount unit to provide, or none")
set_property(CACHE Kind_Mount PROPERTY STRINGS none linux)

set(Kind_Automount
    ${Default_Kind_Automount}
    CACHE STRING "Kind of .automount unit to provide, or none")
set_property(CACHE Kind_Automount PROPERTY STRINGS none linux)

set(Kind_Swap
    ${Default_Kind_Swap}
    CACHE STRING "Kind of .swap unit to provide, or none")
set_property(CACHE Kind_Swap PROPERTY STRINGS none linux)

# computed libraries/settings

if (${Use_Libdevattr})
	set(UDev_Libs devattr prop)
elseif (${Use_Libudev})
	set(UDev_Libs PkgConfig::UDev)
endif ()

if (Have_mq_open_in_rt AND ${Use_MQueue})
	set(MQ_Libs rt)
endif ()

if (${Use_Libcap})
	set(Cap_Libs PkgConfig::Cap)
endif ()

# -------------------------------------------------------------------------------
# computed paths
# -------------------------------------------------------------------------------

# systemdstatedir
set(INSTALL_PKGLOCALSTATE_DIR
    ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${PACKAGE_NAME})

set(SYSTEM_CONFIG_UNIT_PATH ${INSTALL_PKGSYSCONF_DIR}/system)
set(SYSTEM_DATA_UNIT_PATH ${INSTALL_PKGLIB_DIR}/system)
set(SYSTEM_GENERATOR_PATH ${INSTALL_PKGLIBEXEC_DIR}/system-generators)

set(USER_CONFIG_UNIT_PATH ${INSTALL_PKGSYSCONF_DIR}/user)
set(USER_DATA_UNIT_PATH ${INSTALL_PKGLIB_DIR}/user)
set(USER_GENERATOR_PATH ${INSTALL_PKGLIBEXEC_DIR}/user-generators)

# data paths
set(AbsPath_CatalogDatabase ${INSTALL_PKGLOCALSTATE_DIR}/catalog/database)

# binary paths
set(SYSTEMCTL_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/svcctl)
set(SYSTEMD_BINARY_PATH ${INSTALL_PKGLIBEXEC_DIR}/svc.managerd)
set(SYSTEMD_CGROUP_AGENT_AGENT ${INSTALL_PKGLIBEXEC_DIR}/svc.cgroups-agent)
set(SYSTEMD_SHUTDOWN_BINARY_PATH ${INSTALL_PKGLIBEXEC_DIR}/svc.shutdown)
set(SYSTEMD_SLEEP_BINARY_PATH ${INSTALL_PKGLIBEXEC_DIR}/svc.sleep)
set(SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH
    ${INSTALL_PKGLIBEXEC_DIR}/svc.tty-ask-password-agent)
set(SYSTEMD_STDIO_BRIDGE_BINARY_PATH ${INSTALL_PKGLIBEXEC_DIR}/svc.stdio-bridge)
# todo: find
set(POLKIT_AGENT_BINARY_PATH ${CMAKE_INSTALL_FULL_BINDIR}/pkttyagent)

set(BinPath_Runrcng ${INSTALL_PKGLIBEXEC_DIR}/runrcng.sh)

# -------------------------------------------------------------------------------
# actual building commands
# -------------------------------------------------------------------------------

add_library(internal INTERFACE)
target_include_directories(internal INTERFACE common head head/systemd)

add_subdirectory(vendor/iw-cjson)
add_subdirectory(vendor/iw-libev)
# add_subdirectory(vendor/iw-sqlite)

# if (build_doc) or something like that
add_subdirectory(vendor/iw-docbook2mdoc)
add_subdirectory(doc/manual)
# endif

add_subdirectory(lib)
add_subdirectory(cmd)

configure_file(lib/compat/head/config.h.in lib/compat/head/config.h)

# -------------------------------------------------------------------------------
# display enabled options
# -------------------------------------------------------------------------------

function (FShow name flag)
	if (${flag})
		message("  ${name}: ${${flag}}")
	else ()
		message("  ${name}: OFF")
	endif ()
endfunction (FShow)

message("Feature settings (Use flags):")
fshow("Systemd-compatible D-Bus interface" Use_SystemdDBus)
fshow("Systemd-compatible paths & behaviour" Use_SystemdCompat)
fshow("Non-combined /usr and /" HAVE_SPLIT_USR)

message("  Advanced process tracking:")
fshow("    -> GNU/Linux Control Groups (CGroups)" Use_CGroups)
fshow("    -> Kernel Queues PROC event filter" Use_KQProc)

message("  Authentication module:")
fshow("    -> Pluggable AUthentication Modules (PAM)" Use_PAM)

fshow("POSIX Capabilities (libcap)" Use_Libcap)
fshow("POSIX Message Queues" Use_MQueue)
fshow("UDev (libdevattr)" Use_Libdevattr)
fshow("UDev (libudev)" Use_Libudev)

message("Optional units:")
fshow(".device" Kind_Device)
fshow(".mount" Kind_Mount)
fshow(".automount" Kind_Automount)
fshow(".swap" Kind_Swap)

message("Paths:")
fshow("Prefix" CMAKE_INSTALL_PREFIX)
fshow("  -> InitWare-internal executables" INSTALL_PKGLIBEXEC_DIR)
fshow("  -> System-provided InitWare data" INSTALL_PKGLIB_DIR)
fshow("  -> Node-specific InitWare data" INSTALL_PKGSYSCONF_DIR)
fshow("System runtime state" INSTALL_RUNSTATE_DIR)
fshow("User runtime state base" INSTALL_USERSTATE_DIR)
fshow("InitWare runtime state" INSTALL_PKGRUNSTATE_DIR)

# finally, add relevant options to the M4 macro definitions
foreach (option Sys_Plat_Linux Sys_Plat_BSD Sys_Plat_DragonFlyBSD
    Sys_Plat_FreeBSD Sys_Plat_NetBSD Sys_Plat_OpenBSD)
	if (${option})
		list(APPEND M4_Defs "-D${OPTION}=${${option}}")
	endif ()
endforeach ()
