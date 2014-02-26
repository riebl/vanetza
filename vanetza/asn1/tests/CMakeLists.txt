include(UseGTest)
set(VANETZA_MODULE_TEST asn1)

add_asn1c("${CMAKE_CURRENT_SOURCE_DIR}/gen" asn1c_gen_test)
add_gtest(asn1c_wrapper asn1c_wrapper.cpp)
link_gtest(asn1c_wrapper asn1c_gen_test)

