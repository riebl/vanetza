set(CXX_SOURCES
    data_rates.cpp
)
add_vanetza_component(access ${CXX_SOURCES})

add_test_subdirectory(tests)

