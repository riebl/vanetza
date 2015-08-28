set(CXX_SOURCES
    access_category.cpp
    chunk_packet.cpp
    cohesive_packet.cpp
    ethernet_header.cpp
    io_vector.cpp
    mac_address.cpp
    packet.cpp
    proxy_header.cpp
    sockaddr.cpp
)
vanetza_module(net ${CXX_SOURCES})
vanetza_intermodule_dependencies(net common)

add_test_subdirectory(tests)

