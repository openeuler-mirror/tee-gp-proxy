#
#

cmake_minimum_required(VERSION 3.5.1)

project(spiffejwt C CXX)

# include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Introduce variables:
#   - CMAKE_INSTALL_LIBDIR
#   - CMAKE_INSTALL_BINDIR
#   - CMAKE_INSTALL_INCLUDEDIR
include(GNUInstallDirs)


set(LIB_SPIFFEJWT
   ${PROJECT_SOURCE_DIR}/spiffejwt.c
)
# Install Headers:
set(HEADERS_SPIFFEJWT
   ${PROJECT_SOURCE_DIR}/spiffejwt.h
)
install(
    FILES ${HEADERS_SPIFFEJWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}"
)

add_library(spiffejwt SHARED ${LIB_SPIFFEJWT})
target_link_libraries(spiffejwt
        libclient.so
)

# Install lib:
install(
    TARGETS "spiffejwt"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

set(TEST_SPIFFEJWT
    ${PROJECT_SOURCE_DIR}/test_spiffejwt.c
)
add_executable(test_spiffejwt "${TEST_SPIFFEJWT}")
target_link_libraries(
   test_spiffejwt 
   spiffejwt
)

# Install bin:
# install(
#    TARGETS test_spiffejwt
#    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR$}"
# )



