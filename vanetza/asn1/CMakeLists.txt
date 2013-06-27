set(ASN1_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen")
file(GLOB ASN1_SOURCES ${ASN1_GEN_DIR}/*.c)
if(NOT ASN1_SOURCES)
    message(FATAL_ERROR "ASN1 sources missing. Generate them from specification first!")
endif()

include_directories(${ASN1_GEN_DIR})
add_library(asn1 ${ASN1_SOURCES})

