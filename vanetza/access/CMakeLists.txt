set(CXX_SOURCES
    access_category.cpp
    data_rates.cpp
)
add_vanetza_component(access ${CXX_SOURCES})

add_test_subdirectory(tests)

