add_vanetza_component(gnss nmea.cpp)
target_link_libraries(gnss PUBLIC Boost::date_time)

add_test_subdirectory(tests)

