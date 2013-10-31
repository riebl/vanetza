include(UseGTest)
set(VANETZA_MODULE_TEST common)

add_gtest(BitNumber bit_number.cpp)
add_gtest(ByteBuffer byte_buffer.cpp)
add_gtest(ByteBufferSink byte_buffer_sink.cpp)
add_gtest(ByteBufferSource byte_buffer_source.cpp)

