  
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

# -------------------------------------------------------------------------------
# feature checks
# -------------------------------------------------------------------------------

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
	set(EPoll_Compat_Libs PkgConfig::inotify PkgConfig::epoll-shim)
endif ()

find_package(Threads REQUIRED)
find_package(Python COMPONENTS Interpreter)
find_program(GPERF gperf REQUIRED)

# -------------------------------------------------------------------------------
# options configurable by the user
# -------------------------------------------------------------------------------

cmake_dependent_option(USE_CGroups "Use Control Groups" ON
    "NOT SVC_PLATFORM_Linux" OFF)

configure_file(head/systemd/svc-config.h.in head/systemd/svc-config.h)