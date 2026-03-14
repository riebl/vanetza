set(CXX_SOURCES
    archives.cpp
    byte_buffer_convertible.cpp
    byte_buffer_sink.cpp
    byte_buffer_source.cpp
    byte_sequence.cpp
    byte_view.cpp
    clock.cpp
    manual_runtime.cpp
    position_fix.cpp
    unit_interval.cpp
)
add_vanetza_component(common ${CXX_SOURCES})
target_link_libraries(common PUBLIC Boost::date_time)

add_test_subdirectory(tests)
