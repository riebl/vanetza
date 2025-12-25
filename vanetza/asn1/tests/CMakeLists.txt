include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES asn1)

add_gtest(asn1c_wrapper asn1c_wrapper.cpp)
add_gtest(Cpm SOURCES cpm.cpp)
add_gtest(ItsAsn1 SOURCES its.cpp)
add_gtest(ItsAsn1Rel2 SOURCES its_r2.cpp LINK_LIBRARIES asn1_its_r2)
add_gtest(PacketVisitor SOURCES packet_visitor.cpp LINK_LIBRARIES net)
add_gtest(SecurityAsn1 SOURCES security.cpp LINK_LIBRARIES asn1_security)
