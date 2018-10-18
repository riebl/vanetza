set(CXX_SOURCES
    archives.cpp
    byte_buffer_convertible.cpp
    byte_buffer_sink.cpp
    byte_buffer_source.cpp
    byte_sequence.cpp
    byte_view.cpp
    clock.cpp
    manual_runtime.cpp
    unit_interval.cpp
)
add_vanetza_component(common ${CXX_SOURCES})
target_link_libraries(common PUBLIC Boost::date_time)

if(TARGET Threads::Threads)
    target_link_libraries(common INTERFACE Threads::Threads)
endif()

add_test_subdirectory(tests)

