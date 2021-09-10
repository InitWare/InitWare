  
project(InitWare)
cmake_minimum_required(VERSION 3.9)
cmake_policy(VERSION 3.9)

set(PACKAGE_NAME InitWare)
set(PACKAGE_VERSION 0.8alpha)
set(PACKAGE_STRING "${PACKAGE_NAME} version ${PACKAGE_VERSION}")
set(SYSTEMD_VERSION 219)
set(DISTRIBUTION "${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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
	list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE -D__BSD_VISIBLE")
	set(CMAKE_EXTRA_INCLUDE_FILES ${headers})
	check_type_size(${type} ${var})
	cmake_push_check_state(RESET)
endmacro ()

# ------------------------------------------------------------------------------
# feature checks
# ------------------------------------------------------------------------------

# These are default values for some options, but they'll be changed if
# appropriate libraries or features are discovered during configuration.

set(DEFAULT_INSTALL_RUNSTATE_DIR "/var/run")

set(PKGCONF_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if (CMAKE_SYSTEM_NAME MATCHES ".*Linux")
	set(SVC_PLATFORM_Linux TRUE)
	set(DEFAULT_INSTALL_RUNSTATE_DIR "/run")
	add_definitions("-D_GNU_SOURCE")
elseif (CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
	set(SVC_PLATFORM_BSD TRUE)
	set(SVC_PLATFORM_FreeBSD TRUE)
	set(PKGCONF_DIR libdata/pkgconfig)
elseif (CMAKE_SYSTEM_NAME MATCHES "kNetBSD.*|NetBSD.*")
	set(SVC_PLATFORM_BSD TRUE)
	set(SVC_PLATFORM_NetBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
	set(SVC_PLATFORM_BSD TRUE)
	set(SVC_PLATFORM_OpenBSD TRUE)
elseif (CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
	set(SVC_PLATFORM_BSD TRUE)
	set(SVC_PLATFORM_DragonFlyBSD TRUE)
elseif (APPLE)
	set(SVC_PLATFORM_BSD TRUE)
	set(SVC_PLATFORM_MacOS TRUE)
endif ()

if (NOT SVC_PLATFORM_Linux)
	pkg_check_modules(inotify REQUIRED IMPORTED_TARGET libinotify)
	pkg_check_modules(epoll-shim REQUIRED IMPORTED_TARGET epoll-shim)
	set(EPOLL_LIBS PkgConfig::inotify PkgConfig::epoll-shim)
endif ()

find_package(Threads REQUIRED)
find_package(Python COMPONENTS Interpreter)
find_program(GPERF gperf REQUIRED)

check_type_size(pid_t SVC_SIZEOF_PID_T)
check_type_size(uid_t SVC_SIZEOF_UID_T)
check_type_size(gid_t SVC_SIZEOF_GID_T)
check_type_size_in(time_t "sys/time.h" SVC_SIZEOF_TIME_T)
check_type_size_in(rlim_t "sys/resource.h" SVC_SIZEOF_RLIM_T)

check_type_size_in(__compar_fn_t "stdlib.h" SVC_HAVE___compar_fn_t)
check_type_size_in("struct statfs" "sys/statfs.h;sys/statvfs.h" SVC_HAVE_statfs)
check_type_size_in("struct statvfs" "sys/statvfs.h" SVC_HAVE_statvfs)

check_symbol_exists(program_invocation_short_name "errno.h"
		    SVC_HAVE_program_invocation_short_name)

# ------------------------------------------------------------------------------
# options configurable by the user
# ------------------------------------------------------------------------------

cmake_dependent_option(USE_CGroups "Use Control Groups" ON
    "NOT SVC_PLATFORM_Linux" OFF)

set(PKG_DIR_NAME" InitWare")

# Paths, either absolute ("full") or relative ("rel")
set(INSTALL_RUNSTATE_DIR
"${DEFAULT_INSTALL_RUNSTATE_DIR}"
CACHE STRING
    "Full path to the system runtime state directory, e.g. /var/run")

set(INSTALL_PKGRUNSTATE_DIR
"${INSTALL_RUNSTATE_DIR}/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory in which to store the run-time state of \
InitWare, e.g. /var/run/InitWare")

set(INSTALL_USERSTATE_DIR
"${INSTALL_RUNSTATE_DIR}/user"
CACHE STRING
    "Full path to the directory in which to generate subdirectories for runtime \
state of each logged-in user, e.g. /var/run/user")

set(INSTALL_PKGLIB_DIR
"${CMAKE_INSTALL_PREFIX}/lib/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory for storing system-provided, read-only InitWare \
configuration and unit-files (not actual libraries). ")

set(INSTALL_PKGLIBEXEC_DIR
"${CMAKE_INSTALL_FULL_LIBEXECDIR}/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory for storing executables not \
intended for running by the user, e.g. agents and generators.")

set(INSTALL_PKGSYSCONF_DIR
"${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PKG_DIR_NAME}"
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


# -------------------------------------------------------------------------------
# computed paths
# -------------------------------------------------------------------------------

# systemdstatedir
set(INSTALL_PKGLOCALSTATE_DIR
    ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${PKG_DIR_NAME})

set(SYSTEM_CONFIG_UNIT_PATH ${INSTALL_PKGSYSCONF_DIR}/system)
set(SYSTEM_DATA_UNIT_PATH ${INSTALL_PKGLIB_DIR}/system)
set(SYSTEM_GENERATOR_PATH ${INSTALL_PKGLIBEXEC_DIR}/system-generators)

set(USER_CONFIG_UNIT_PATH ${INSTALL_PKGSYSCONF_DIR}/user)
set(USER_DATA_UNIT_PATH ${INSTALL_PKGLIB_DIR}/user)
set(USER_GENERATOR_PATH ${INSTALL_PKGLIBEXEC_DIR}/user-generators)

configure_file(head/systemd/svc-config.h.in head/systemd/svc-config.h)

# ------------------------------------------------------------------------------
# the build proper
# ------------------------------------------------------------------------------

add_subdirectory(lib)