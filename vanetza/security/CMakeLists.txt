find_package(Boost COMPONENTS serialization REQUIRED)

set(CXX_SOURCES
    ecc_point.cpp
    public_key.cpp
    length_coding.cpp
    int_x.cpp
)

vanetza_module(security ${CXX_SOURCES})

vanetza_module_property(security INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIRS}
)

vanetza_module_dependencies(security
    ${Boost_SERIALIZATION_LIBRARY}
)

add_subdirectory(tests)
