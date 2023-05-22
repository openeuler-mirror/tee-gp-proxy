#

cmake_minimum_required(VERSION 3.5.1)

project(libdbusc_gpw C CXX)

# set(CMAKE_C_FLAGS "${CMAKE_}")
# set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")
# include_directories(${CMAKE_CURRENT_BINARY_DIR}/../include/)
include_directories(/usr/include/dbus-1.0/)
include_directories(/usr/lib64/dbus-1.0/include/)

# Introduce variables:
#   - CMAKE_INSTALL_LIBDIR
#   - CMAKE_INSTALL_BINDIR
#   - CMAKE_INSTALL_INCLUDEDIR
include(GNUInstallDirs)

set(LIB_DBUSC_GPW
   ${PROJECT_SOURCE_DIR}/dbusc_gpw.c
)
# Install Headers:
set(HEADERS_DBUSC_GPW
   dbusc_gpw.h
)
install(
   FILES ${HEADERS_DBUSC_GPW}
   DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}"
)

add_library(dbusc_gpw SHARED ${LIB_DBUSC_GPW})
target_link_libraries(dbusc_gpw
   libdbus-1.so
)
# set_target_properties(dbusc_gpw
#   PROPERTIES IMPORTED_LOCATION
# )  

# Install lib:
install(
    TARGETS "dbusc_gpw"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)
