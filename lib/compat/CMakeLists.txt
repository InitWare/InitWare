#
# Library collecting basic definitions and compatibility functions not available
# on certain platforms.
#

configure_file(head/compat.h.in head/compat.h)

add_library(compat compat.c ${CMAKE_CURRENT_BINARY_DIR}/head/compat.h)
target_include_directories(compat PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/head)
target_link_libraries(compat ${EPoll_Compat_Libs})