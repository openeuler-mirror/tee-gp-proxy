cmake_minimum_required(VERSION 3.5.1)

project(testcase C CXX)

# set(CMAKE_C_FLAGS "${CMAKE_}")
# set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)

# include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_executable(testcase testcase.c)
target_link_libraries(
   testcase
   pthread
   libteecc.so
   libdbusc_jwt.so
)
