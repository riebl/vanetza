add_vanetza_component(gnss nmea.cpp)
target_link_libraries(gnss Boost::boost)

add_test_subdirectory(tests)

