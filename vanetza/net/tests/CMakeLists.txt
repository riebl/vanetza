include(UseGTest)
prepare_gtest(net)

add_gtest(ChunkPacket chunk_packet.cpp)
add_gtest(CohesivePacket cohesive_packet.cpp)
add_gtest(EthernetHeader ethernet_header.cpp)
add_gtest(MacAddress mac_address.cpp)
add_gtest(OsiLayer osi_layer.cpp)

