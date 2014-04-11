include(UseGTest)
set(VANETZA_MODULE_TEST asn1)

set(ASN1C_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen")
asn1c_sources(ASN1C_SOURCES ${ASN1C_GEN_DIR})

add_gtest(asn1c_wrapper asn1c_wrapper.cpp ${ASN1C_SOURCES})

