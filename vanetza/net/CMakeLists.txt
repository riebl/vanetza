set(CXX_SOURCES
    access_category.cpp
    ethernet_header.cpp
    io_vector.cpp
    mac_address.cpp
    packet.cpp
    sockaddr.cpp
)
vanetza_module(net ${CXX_SOURCES})

add_subdirectory(tests)

