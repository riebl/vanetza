find_package(Boost COMPONENTS serialization REQUIRED)

set(CXX_SOURCES
    basic_elements.cpp
    certificate.cpp
    ecc_point.cpp
    encryption_parameter.cpp
    public_key.cpp
    length_coding.cpp
    int_x.cpp
    signature.cpp
    signer_info.cpp
    subject_attribute.cpp
    subject_info.cpp
    recipient_info.cpp
    region.cpp
    validity_restriction.cpp
)

vanetza_module(security ${CXX_SOURCES})

vanetza_module_property(security INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIRS}
)

vanetza_module_dependencies(security
    ${Boost_SERIALIZATION_LIBRARY}
)

add_subdirectory(tests)
