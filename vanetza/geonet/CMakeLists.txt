find_package(Boost COMPONENTS serialization REQUIRED)
find_package(GeographicLib REQUIRED)

set(CXX_SOURCES
    address.cpp
    areas.cpp
    basic_header.cpp
    beacon_header.cpp
    common_header.cpp
    data_confirm.cpp
    data_indication.cpp
    data_request.cpp
    header_type.cpp
    mib.cpp
    packet.cpp
    sequence_number.cpp
    lifetime.cpp
    location_table.cpp
    packet_buffer.cpp
    position_vector.cpp
    timestamp.cpp
    traffic_class.cpp
)

vanetza_module(geonet ${CXX_SOURCES})
vanetza_intermodule_dependencies(geonet dcc net)

vanetza_module_property(geonet INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIRS}
    ${GEOGRAPHICLIB_INCLUDE_DIRS}
)
vanetza_module_dependencies(geonet
    ${Boost_SERIALIZATION_LIBRARY}
    ${GEOGRAPHICLIB_LIBRARIES}
)

option(VANETZA_GEONET_USE_PACKET_VARIANT "Use packet variant for GeoNet UpPackets" OFF)
if(VANETZA_GEONET_USE_PACKET_VARIANT)
    set(_compile_definition "VANETZA_GEONET_USE_PACKET_VARIANT")
    vanetza_module_property(geonet COMPILE_DEFINITIONS ${_compile_definition})
    vanetza_module_property(geonet INTERFACE_COMPILE_DEFINITIONS ${_compile_definition})
endif()

add_subdirectory(tests)
