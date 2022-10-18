#
#

cmake_minimum_required(VERSION 3.5.1)

project(teecc C CXX)

include(common.cmake)

# Proto file
get_filename_component(gt_proto "./protos/gt.proto" ABSOLUTE)
get_filename_component(gt_proto_path "${gt_proto}" PATH)
# [[get_filename_component(proto "../protos/${proto_name}.proto" ABSOLUTE)
# get_filename_component(proto_dir "${proto}" DIRECTORY)]]

# Generated sources
set(gt_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/gt.pb.cc")
set(gt_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/gt.pb.h")
set(gt_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/gt.grpc.pb.cc")
set(gt_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/gt.grpc.pb.h")

add_custom_command(
      OUTPUT "${gt_proto_srcs}" "${gt_proto_hdrs}" "${gt_grpc_srcs}" "${gt_grpc_hdrs}"  
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${gt_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${gt_proto}"
      DEPENDS "${gt_proto}"
)

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories(/usr/include/dbus-1.0/)
include_directories(/usr/lib64/dbus-1.0/include/)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../include)

# Introduce variables:
#   - CMAKE_INSTALL_LIBDIR
#   - CMAKE_INSTALL_BINDIR
#   - CMAKE_INSTALL_INCLUDEDIR
include(GNUInstallDirs)


set(TEECC_NAME "teecc")
set(LIB_TEECC
   ${PROJECT_SOURCE_DIR}/teecc.cc
   ${gt_grpc_srcs}
   ${gt_proto_srcs}   
)
# Install Headers:
set(HEADERS_TEECC
   ${PROJECT_SOURCE_DIR}/include/teecc/teec_client_api.h
   ${PROJECT_SOURCE_DIR}/include/teecc/tee_client_constants.h
   ${PROJECT_SOURCE_DIR}/include/teecc/tee_client_list.h
   ${PROJECT_SOURCE_DIR}/include/teecc/tee_client_log.h
   ${PROJECT_SOURCE_DIR}/include/teecc/tee_client_type.h
)
install(
   FILES ${HEADERS_TEECC}
   DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TEECC_NAME}/${TARGET_NAME}"
)


# gt_grpc_proto
add_library(gt_grpc_proto
  ${gt_grpc_srcs}
  ${gt_grpc_hdrs}
  ${gt_proto_srcs}
  ${gt_proto_hdrs}
)
target_link_libraries(gt_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF}
)



add_library(teecc SHARED 
   ${LIB_TEECC}
)
target_link_libraries(teecc
    gt_grpc_proto
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF}
	 yaml-cpp.a
)

# Install lib
install(
    TARGETS  "teecc"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)
# Install config file
set(teecc_config_dir "$ENV{HOME}/.teecc")
# install(
#   DIRECTORY
#   DESTINATION ${gpp_config_dir})
install(
   FILES "conf/teecc_config.yaml"
   DESTINATION ${teecc_config_dir}
)
# Install certs
set(teecc_certs_dir "$ENV{HOME}/.teecc/certs")
install(
   FILES
      "certs/ca_crt.pem"
      "certs/client_key.pem"
      "certs/client_crt.pem"
      "certs/gen_client_keycsr.sh"
      "certs/msg.txt"
      "certs/check_ca_crt.sh"
      "certs/check_client_key.sh"
      "certs/check_client_crt.sh"
   DESTINATION ${teecc_certs_dir}
)
