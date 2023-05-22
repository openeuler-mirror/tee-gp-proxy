#

cmake_minimum_required(VERSION 3.5.1)

project(dbus_jwt C CXX)

# set(CMAKE_C_FLAGS "${CMAKE_}")
# set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)

# include_directories("${CMAKE_CURRENT_BINARY_DIR}")
# include_directories(${CMAKE_CURRENT_BINARY_DIR}/../include/)
include_directories(/usr/include/dbus-1.0/)
include_directories(/usr/lib64/dbus-1.0/include/)

# Introduce variables:
#   - CMAKE_INSTALL_LIBDIR
#   - CMAKE_INSTALL_BINDIR
#   - CMAKE_INSTALL_INCLUDEDIR
include(GNUInstallDirs)


set(lib_dbusc_jwt
   ${PROJECT_SOURCE_DIR}/dbusc_jwt.c
)
# Install Headers:
set(HEADERS_DBUSC_JWT
   ${PROJECT_SOURCE_DIR}/dbusc_jwt.h
)
install(
    FILES ${HEADERS_DBUSC_JWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}"
)

add_library(dbusc_jwt SHARED ${lib_dbusc_jwt})
target_link_libraries(
   dbusc_jwt
   libdbus-1.so
)

# Install lib:
install(
    TARGETS "dbusc_jwt"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)


set(dbuss_fetchjwt
   ${PROJECT_SOURCE_DIR}/dbuss_fetchjwt.c
)
add_executable(dbuss_fetchjwt "${dbuss_fetchjwt}")
target_link_libraries(
   dbuss_fetchjwt
   libdbus-1.so
   spiffejwt
)

set(dbuss_validatejwt
   ${PROJECT_SOURCE_DIR}/dbuss_validatejwt.c
)
add_executable(dbuss_validatejwt "${dbuss_validatejwt}")
target_link_libraries(
   dbuss_validatejwt
   libdbus-1.so
   spiffejwt
)

# Install bin:
install(
   TARGETS "dbuss_fetchjwt" "dbuss_validatejwt"
   RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR$}"
)
