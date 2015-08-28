set(CXX_SOURCES
    byte_buffer_convertible.cpp
    byte_buffer_sink.cpp
    byte_buffer_source.cpp
    byte_sequence.cpp
    byte_view.cpp
)
vanetza_module(common ${CXX_SOURCES})

add_test_subdirectory(tests)

