  
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
	list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE -D__BSD_VISIBLE")
endmacro ()

# Add a list of variables to the M4 invocation parameters
macro(add_to_m4_params)
	foreach(arg IN ITEMS ${ARGN})
		if (arg AND ${arg})
			string(APPEND M4_PARAMS " -D${arg}=${${arg}}")
		endif ()
	endforeach()
endmacro()

function(build_m4 in out)
	# CMake has outrageously incomprehensible escaping rules; we try to circumvent
	# this madness as best we can here.
	set(command "m4 ${M4_PARAMS} -P < ${in} > ${out}")
	add_custom_command(
	    OUTPUT ${out}
	    VERBATIM COMMAND sh -c ${command}
	    DEPENDS ${in})
endfunction(build_m4)


# ------------------------------------------------------------------------------
# feature checks
# ------------------------------------------------------------------------------

# These are default values for some options, but they'll be changed if
# appropriate libraries or features are discovered during configuration.

set(DEFAULT_SVC_RUNSTATEDIR "/var/run")

set(PKGCONF_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if (CMAKE_SYSTEM_NAME MATCHES ".*Linux")
	set(SVC_PLATFORM_Linux TRUE)
	set(DEFAULT_SVC_RUNSTATEDIR "/run")
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
else ()
	pkg_check_modules(libcap IMPORTED_TARGET libcap)
	pkg_check_modules(kqueue REQUIRED IMPORTED_TARGET libkqueue)
	set(KQ_LIBS PkgConfig::kqueue)
endif ()

find_package(Threads REQUIRED)
find_package(Python COMPONENTS Interpreter)
find_program(GPERF gperf REQUIRED)

check_include_file(sys/endian.h HAVE_sys_endian_h)
check_include_file(endian.h HAVE_endian_h)
check_include_file(mntent.h HAVE_mntent_h)

check_type_size(pid_t SVC_SIZEOF_PID_T)
check_type_size(uid_t SVC_SIZEOF_UID_T)
check_type_size(gid_t SVC_SIZEOF_GID_T)
check_type_size_in(time_t "sys/time.h" SVC_SIZEOF_TIME_T)
check_type_size_in(rlim_t "sys/resource.h" SVC_SIZEOF_RLIM_T)

check_type_size_in(__compar_fn_t "stdlib.h" SVC_HAVE___compar_fn_t)
check_type_size_in("struct statfs" "sys/statfs.h;sys/statvfs.h" SVC_HAVE_statfs)
check_type_size_in("struct statvfs" "sys/statvfs.h" SVC_HAVE_statvfs)
check_type_size_in("struct ucred" "sys/socket.h" HAVE_socket_struct_ucred)

check_symbol_exists(canonicalize_file_name "stdlib.h" HAVE_canonicalize_file_name)
check_symbol_exists(environ "unistd.h" HAVE_environ)
check_symbol_exists(get_current_dir_name "unistd.h" SVC_HAVE_get_current_dir_name)
check_symbol_exists(gettid "unistd.h" HAVE_gettid)
check_symbol_exists(name_to_handle_at "fcntl.h" HAVE_name_to_handle_at)
check_function_exists(mempcpy HAVE_mempcpy)
check_symbol_exists(program_invocation_short_name "errno.h"
		    SVC_HAVE_program_invocation_short_name)
check_function_exists(secure_getenv HAVE_secure_getenv)
check_function_exists(__secure_getenv HAVE___secure_getenv)

# ------------------------------------------------------------------------------
# options configurable by the user
# ------------------------------------------------------------------------------

option(SVC_USE_CGroups "Use Control Groups" ON)
cmake_dependent_option(SVC_USE_libcap "Use Capabilities (libcap)" ON
    "libcap_FOUND" OFF)
option(SVC_USE_systemd_paths "Include the default systemd unit-file paths" OFF)

option(SVC_USE_sessiond "Build the Session Manager" ON)

set(PKG_DIR_NAME
"InitWare"
CACHE STRING
    "Default name of InitWare subdirectories (can be set to 'systemd' for \
systemd compatibility.)")

set(SVC_RUNSTATEDIR
"${DEFAULT_SVC_RUNSTATEDIR}"
CACHE STRING
    "Full path to the system runtime state directory, e.g. /var/run")

set(SVC_PKGRUNSTATEDIR
"${SVC_RUNSTATEDIR}/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory in which to store the run-time state of \
InitWare, e.g. /var/run/InitWare")

set(SVC_USERRUNSTATEDIR
"${SVC_RUNSTATEDIR}/user"
CACHE STRING
    "Full path to the directory in which to generate subdirectories for runtime \
state of each logged-in user, e.g. /var/run/user")

set(SVC_PKGLIBDIR
"${CMAKE_INSTALL_PREFIX}/lib/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory for storing system-provided, read-only InitWare \
configuration and unit-files (not actual libraries). ")

set(SVC_PKGLIBEXECDIR
"${CMAKE_INSTALL_FULL_LIBEXECDIR}/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory for storing executables not \
intended for running by the user, e.g. agents and generators.")

set(SVC_PKGSYSCONFDIR
"${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PKG_DIR_NAME}"
CACHE STRING
    "Full path to the directory for storing  \
node-specific, administrator-modifiable configuration and unit-files.")

set(SVC_DBUSSERVICESDIR
"${CMAKE_INSTALL_FULL_DATAROOTDIR}/dbus-1/system-services"
CACHE STRING
    "Full path to the directory for storing D-Bus system service files.")

set(SVC_DBUSCONFDIR
"${CMAKE_INSTALL_FULL_DATAROOTDIR}/dbus-1/system.d"
CACHE STRING
    "Full path to the directory for storing D-Bus system service configuration."
)

set(SVC_POLKITACTIONDIR
"${CMAKE_INSTALL_FULL_DATAROOTDIR}/polkit-1/actions"
CACHE STRING
    "Full path to the directory for storing D-Bus system service configuration."
)

# -------------------------------------------------------------------------------
# computed paths
# -------------------------------------------------------------------------------

# systemdstatedir
set(SVC_PKGLOCALSTATEDIR
    ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${PKG_DIR_NAME})

set(SYSTEM_CONFIG_UNIT_PATH ${SVC_PKGSYSCONFDIR}/system)
set(SYSTEM_DATA_UNIT_PATH ${SVC_PKGLIBDIR}/system)
set(SYSTEM_GENERATOR_PATH ${SVC_PKGLIBEXECDIR}/system-generators)

set(USER_CONFIG_UNIT_PATH ${SVC_PKGSYSCONFDIR}/user)
set(USER_DATA_UNIT_PATH ${SVC_PKGLIBDIR}/user)
set(USER_GENERATOR_PATH ${SVC_PKGLIBEXECDIR}/user-generators)

configure_file(head/systemd/svc-config.h.in head/systemd/svc-config.h)

# ------------------------------------------------------------------------------
# the build proper
# ------------------------------------------------------------------------------

add_to_m4_params(SVC_PLATFORM_Linux SVC_PLATFORM_BSD UnsSet)

add_subdirectory(cmd)
add_subdirectory(lib)

# ------------------------------------------------------------------------------
# show options settings
# ------------------------------------------------------------------------------

function (FShow flag)
	if (${flag})
		message("  ${flag}: ${${flag}}")
	else ()
		message("  ${flag}: OFF")
	endif ()
endfunction (FShow)

message("Feature settings (Use flags):")
fshow(SVC_USE_CGroups)
fshow(SVC_USE_libcap)
fshow(SVC_USE_systemd_paths)
fshow(SVC_USE_sessiond)

message("Paths:")
fshow(CMAKE_INSTALL_PREFIX)
fshow(SVC_PKGLIBEXECDIR)
fshow(SVC_PKGLIBDIR)
fshow(SVC_PKGSYSCONFDIR)
fshow(SVC_RUNSTATEDIR)
fshow(SVC_USERRUNSTATEDIR)
fshow(SVC_PKGRUNSTATEDIR)
