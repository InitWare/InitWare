get_filename_component(NAME ${CMAKE_ARGV3} NAME)

file(READ ${CMAKE_ARGV3} TEXT)

string(REPLACE "." "_" NAME ${NAME})
string(REPLACE "-" "_" NAME ${NAME})

string(REPLACE "\\" "\\\\" TEXT "${TEXT}")
string(REPLACE "\"" "\\\"" TEXT "${TEXT}")
string(REPLACE "\n" "\\n\"\n\"" TEXT "${TEXT}")

set(CODE "#ifndef ${NAME}_H_\n#define ${NAME}_H_\nstatic const char * k${NAME} = \"${TEXT}\";\n#endif\n")
file(WRITE ${CMAKE_ARGV4} "${CODE}")