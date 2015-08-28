include(UseGTest)
set(ASN1C_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen")
asn1c_sources(ASN1C_SOURCES ${ASN1C_GEN_DIR})

prepare_gtest(asn1 ${ASN1C_SOURCES})
add_gtest(asn1c_wrapper asn1c_wrapper.cpp)

