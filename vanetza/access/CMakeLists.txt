set(CXX_SOURCES
    access_category.cpp
    data_rates.cpp
    g5_link_layer.cpp
)
add_vanetza_component(access ${CXX_SOURCES})
target_link_libraries(access PUBLIC net)

add_test_subdirectory(tests)

