set(CXX_SOURCES
    access_category.cpp
    ethernet_header.cpp
    io_vector.cpp
    linux_packet_socket.cpp
    mac_address.cpp
    packet.cpp
    sockaddr.cpp
    socket_descriptor.cpp
)

find_package(Boost COMPONENTS system)
if(Boost_SYSTEM_FOUND)
    list(APPEND CXX_SOURCES telnet_client.cpp)
endif()

vanetza_module(net ${CXX_SOURCES})

if(Boost_SYSTEM_FOUND)
    vanetza_module_property(net INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
    vanetza_module_dependencies(net ${Boost_SYSTEM_LIBRARY})
endif()

