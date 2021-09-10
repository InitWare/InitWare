add_library(bsdcompat compat.c)
target_include_directories(bsdcompat
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/head>
    	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/head/systemd>
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/head>
    	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/head/systemd>)