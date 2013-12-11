include(UseGTest)
set(VANETZA_MODULE_TEST asn1)

set(ASN1_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen")
file(GLOB ASN1_SOURCES ${ASN1_GEN_DIR}/*.c)
include_directories(${ASN1_GEN_DIR})

add_gtest(asn1c_wrapper asn1c_wrapper.cpp ${ASN1_SOURCES})

