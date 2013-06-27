find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

set(CXX_SOURCES
    ethernet_header.cpp
    io_vector.cpp
    linux_packet_socket.cpp
    mac_address.cpp
    packet.cpp
    socket_descriptor.cpp
    telnet_client.cc
)
vanetza_module(net ${CXX_SOURCES})
vanetza_module_dependencies(net ${Boost_LIBRARIES})
