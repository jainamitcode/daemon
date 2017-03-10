cmake_minimum_required (VERSION 3.6)
project (daemon)
# The version number.
set (Daemon_VERSION_MAJOR 1)
set (Daemon_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
# these are available as defines in h.in file
configure_file (
  "${PROJECT_SOURCE_DIR}/DaemonConfig.h.in"
  "${PROJECT_BINARY_DIR}/DaemonConfig.h"
  )
 
# add the binary tree to the search path for include files
# so that we will find DaemonConfig.h
include_directories("${PROJECT_BINARY_DIR}")

# find all source files under src directory and use them to
# build our executable
file(GLOB SOURCES "src/*.c")

add_executable(daemon ${SOURCES})
