find_package(Boost COMPONENTS serialization REQUIRED)

set(CXX_SOURCES
    basic_elements.cpp
    certificate.cpp
    ecc_point.cpp
    encryption_parameter.cpp
    header_field.cpp
    payload.cpp
    public_key.cpp
    length_coding.cpp
    int_x.cpp
    secured_message.cpp
    serialization.cpp
    signature.cpp
    signer_info.cpp
    subject_attribute.cpp
    subject_info.cpp
    recipient_info.cpp
    region.cpp
    trailer_field.cpp
    validity_restriction.cpp
)

vanetza_module(security ${CXX_SOURCES})

vanetza_module_property(security INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIRS}
)

vanetza_module_link_libraries(security
    ${Boost_SERIALIZATION_LIBRARY}
)

add_test_subdirectory(tests)
