include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES asn1)

add_gtest(asn1c_wrapper asn1c_wrapper.cpp)
add_gtest(PacketVisitor SOURCES packet_visitor.cpp LINK_LIBRARIES net)
add_gtest(SecurityAsn1 SOURCES security.cpp LINK_LIBRARIES asn1_security)

