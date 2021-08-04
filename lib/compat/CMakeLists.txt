#
# Library collecting basic definitions and compatibility functions not available
# on certain platforms.
#

add_library(compat compat.c parse-printf-format.c strtonum.c
    ${CMAKE_CURRENT_BINARY_DIR}/head/config.h)
target_include_directories(compat PUBLIC head ${CMAKE_CURRENT_BINARY_DIR}/head)
target_link_libraries(compat ${EPoll_Compat_Libs})