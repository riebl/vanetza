set(CXX_SOURCES
    byte_buffer_convertible.cpp
    byte_buffer_sink.cpp
    byte_buffer_source.cpp
)
vanetza_module(common ${CXX_SOURCES})

add_subdirectory(tests)

