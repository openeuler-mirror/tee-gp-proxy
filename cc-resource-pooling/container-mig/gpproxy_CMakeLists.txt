#
#

cmake_minimum_required(VERSION 3.5.1)

project(gpp C CXX)

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


add_executable(gpproxy
	"gpproxy.cc"
	${gt_grpc_srcs}
    ${gt_proto_srcs}
)
target_link_libraries(gpproxy
    gt_grpc_proto
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF}
    libdbusc_gpw.so
    libdbusc_jwt.so
    yaml-cpp.a
)

# Install bin
install(
   TARGETS gpproxy
   RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
# Install config file
set(gpp_config_dir "$ENV{HOME}/.gpp")
install(
   FILES "conf/gpproxy_config.yaml"
   DESTINATION ${gpp_config_dir}
)  
# Install certs
set(gpp_certs_dir "$ENV{HOME}/.gpp/certs")
install(
   FILES 
      "certs/server_key.pem" 
      "certs/server_crt.pem" 
      "certs/ca_key.pem"
      "certs/ca_crt.pem"
      "certs/gen_ca_keycrt.sh"
      "certs/gen_server_keycrt.sh"
      "certs/gen_client_keycsr.sh"
      "certs/msg.txt"
      "certs/check_ca_key.sh"
      "certs/check_ca_crt.sh"
      "certs/check_server_key.sh"
      "certs/check_server_crt.sh"
      "certs/check_client_key.sh"
      "certs/check_client_crt.sh"
      "certs/gen_ca_crt.sh"
      "certs/gen_server_crt.sh"
      "certs/gen_client_crt.sh"
   DESTINATION ${gpp_certs_dir}
)  
