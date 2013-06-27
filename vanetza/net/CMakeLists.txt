set(CXX_SOURCES
    ethernet_header.cpp
    io_vector.cpp
    linux_packet_socket.cpp
    mac_address.cpp
    packet.cpp
    socket_descriptor.cpp
    telnet_client.cc
)

find_package(Boost COMPONENTS system)
if(Boost_SYSTEM_FOUND)
    list(APPEND CXX_SOURCES telnet_client.cc)
endif()

vanetza_module(net ${CXX_SOURCES})

if(Boost_SYSTEM_FOUND)
    vanetza_module_property(net INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
    vanetza_module_dependencies(net ${Boost_SYSTEM_LIBRARY})
endif()
