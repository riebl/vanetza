add_vanetza_component(geodesy
    country_data_reader.cpp
    country_database.cpp
    geodesy.cpp
    haversine.cpp
)

if(VANETZA_WITH_GEOGRAPHICLIB)
    target_sources(geodesy PRIVATE geographiclib.cpp)
    target_link_libraries(geodesy PRIVATE GeographicLib::GeographicLib)
    target_compile_definitions(geodesy PUBLIC VANETZA_WITH_GEOGRAPHICLIB)
endif()

if(VANETZA_EMBED_COUNTRY_DATA)
    find_program(UV_EXECUTABLE uv REQUIRED)
    set(VANETZA_COUNTRY_DATA_RESOLUTION "50m" CACHE STRING
        "Natural Earth resolution for country data (110m, 50m, 10m)")
    set_property(CACHE VANETZA_COUNTRY_DATA_RESOLUTION PROPERTY STRINGS 110m 50m 10m)

    set(_tool_dir "${PROJECT_SOURCE_DIR}/tools/country-data")
    set(_country_bin "${CMAKE_CURRENT_BINARY_DIR}/country_data.bin")
    set(_embedded_cpp "${CMAKE_CURRENT_BINARY_DIR}/country_data_embedded.cpp")

    add_custom_command(
        OUTPUT "${_country_bin}"
        COMMAND "${UV_EXECUTABLE}" run "${_tool_dir}/convert.py"
            --resolution "${VANETZA_COUNTRY_DATA_RESOLUTION}"
            --output "${_country_bin}"
        DEPENDS "${_tool_dir}/convert.py"
        COMMENT "Converting Natural Earth ${VANETZA_COUNTRY_DATA_RESOLUTION} to country data binary"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "${_embedded_cpp}"
        COMMAND "${UV_EXECUTABLE}" run "${_tool_dir}/embed.py"
            --input "${_country_bin}"
            --output "${_embedded_cpp}"
        DEPENDS "${_country_bin}" "${_tool_dir}/embed.py"
        COMMENT "Generating embedded country data source"
        VERBATIM
    )

    target_sources(geodesy PRIVATE "${_embedded_cpp}")
    target_link_libraries(geodesy PRIVATE common)
    target_compile_definitions(geodesy PUBLIC VANETZA_WITH_EMBEDDED_COUNTRY_DATA)
endif()

add_test_subdirectory(tests)
