find_package(CapnProto CONFIG)
if(CapnProto_FOUND)
    message(STATUS "Enabled Vanetza RPC feature")
    capnp_generate_cpp(CAPNP_SOURCES CAPNP_HEADERS vanetza.capnp)
    add_vanetza_component(rpc
      asio_event_port.cpp
      asio_stream.cpp
      link_layer_client.cpp
      ${CAPNP_SOURCES} ${CAPNP_HEADERS})
    target_include_directories(rpc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(rpc PUBLIC CapnProto::capnp-rpc)
else()
    message(STATUS "Disabled Vanetza RPC feature")
endif()
