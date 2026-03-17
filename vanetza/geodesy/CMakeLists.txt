add_vanetza_component(geodesy
    geodesy.cpp
    haversine.cpp
)

if(VANETZA_WITH_GEOGRAPHICLIB)
    target_sources(geodesy PRIVATE geographiclib.cpp)
    target_link_libraries(geodesy PRIVATE GeographicLib::GeographicLib)
    target_compile_definitions(geodesy PUBLIC VANETZA_WITH_GEOGRAPHICLIB)
endif()

add_test_subdirectory(tests)
