find_package(Boost COMPONENTS serialization REQUIRED)

set(CXX_SOURCES
    byte_buffer_convertible.cpp
    byte_buffer_sink.cpp
    byte_buffer_source.cpp
    byte_sequence.cpp
    byte_view.cpp
)
vanetza_module(common ${CXX_SOURCES})
vanetza_module_property(common INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
vanetza_module_link_libraries(common ${Boost_SERIALIZATION_LIBRARY})

add_test_subdirectory(tests)

