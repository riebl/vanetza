include(UseAsn1c)
add_asn1c("${CMAKE_CURRENT_SOURCE_DIR}/gen" asn1c_gen)
vanetza_export_target(asn1c_gen)

set(CXX_SOURCES asn1c_wrapper.cpp)
vanetza_module(asn1 ${CXX_SOURCES})
vanetza_module_dependencies(asn1 asn1c_gen)

add_subdirectory(tests)

