#include <gtest/gtest.h>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/byte_buffer_source.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/iostreams/stream_buffer.hpp>

using vanetza::ByteBuffer;
using vanetza::InputArchive;
using vanetza::OutputArchive;
using namespace vanetza::security;

TEST(LengthEncoding, count_leading_ones)
{
    EXPECT_EQ(0, count_leading_ones(0x00));
    EXPECT_EQ(1, count_leading_ones(0x80));
    EXPECT_EQ(1, count_leading_ones(0x81));
    EXPECT_EQ(1, count_leading_ones(0xa0));
    EXPECT_EQ(1, count_leading_ones(0xa1));
    EXPECT_EQ(2, count_leading_ones(0xd3));
    EXPECT_EQ(3, count_leading_ones(0xe8));
    EXPECT_EQ(7, count_leading_ones(0xfe));
    EXPECT_EQ(8, count_leading_ones(0xff));
}

TEST(LengthEncoding, encode_length)
{
    EXPECT_EQ(ByteBuffer { 0x00 }, encode_length(0));
    EXPECT_EQ(ByteBuffer { 5 }, encode_length(5));
    EXPECT_EQ(ByteBuffer { 123 }, encode_length(123));
    EXPECT_EQ(ByteBuffer { 127 }, encode_length(127));
    EXPECT_EQ((ByteBuffer { 0x80, 128 }), encode_length(128));
    EXPECT_EQ((ByteBuffer { 0xbf, 0xff }), encode_length(0x3fff));
    EXPECT_EQ((ByteBuffer { 0x81, 0xff }), encode_length(0x01ff));
    EXPECT_EQ((ByteBuffer { 0xdf, 0xff, 0xff }), encode_length(0x1fffff));
    EXPECT_EQ((ByteBuffer { 0xe0, 0x20, 0x00, 0x00 }), encode_length(0x200000));

    EXPECT_EQ(ByteBuffer { 0x0a }, encode_length(10));
    EXPECT_EQ((ByteBuffer { 0x88, 0x88 }), encode_length(2184));
}

TEST(LengthEncoding, decode_length_empty_buffer)
{
    ByteBuffer buffer;
    auto decoded = decode_length(buffer);
    EXPECT_EQ(buffer.end(), std::get<0>(decoded));
    EXPECT_EQ(0, std::get<1>(decoded));
}

TEST(LengthEncoding, decode_length_zero_size)
{
    ByteBuffer buffer { 0x00, 0xC0, 0xFF, 0xEE };
    auto decoded = decode_length(buffer);
    EXPECT_EQ(std::next(buffer.begin()), std::get<0>(decoded));
    EXPECT_EQ(0, std::get<1>(decoded));
}

TEST(LengthEncoding, decode_length_prefix_too_long)
{
    ByteBuffer buffer { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xba, 0xbe };
    auto decoded = decode_length(buffer);
    EXPECT_EQ(buffer.begin(), std::get<0>(decoded));
    EXPECT_EQ(0, std::get<1>(decoded));
}

TEST(LengthEncoding, decode_length_buffer_too_short)
{
    ByteBuffer buffer { 0x02, 0xde };
    auto decoded_tuple = decode_length(buffer);
    EXPECT_EQ(std::next(buffer.begin()), std::get<0>(decoded_tuple));
    EXPECT_EQ(2, std::get<1>(decoded_tuple));
}

TEST(LengthEncoding, decode_length_good)
{
    ByteBuffer buffer { 0xe0, 0x00, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    auto decoded_tuple = decode_length(buffer);
    EXPECT_EQ(std::next(buffer.begin(), 4), std::get<0>(decoded_tuple));
    EXPECT_EQ(4, std::get<1>(decoded_tuple));
}

TEST(LengthEncoding, serialize_length)
{
    ByteBuffer buf;
    auto serialize_length_into_buffer = [&buf](std::size_t length) {
        vanetza::byte_buffer_sink sink(buf);
        boost::iostreams::stream_buffer<vanetza::byte_buffer_sink> stream(sink);
        OutputArchive oa(stream);
        serialize_length(oa, length);
    };

    serialize_length_into_buffer(0x200000);
    ASSERT_EQ(4, buf.size());
    EXPECT_EQ(0xE0, buf[0]);
    EXPECT_EQ(0x20, buf[1]);
    EXPECT_EQ(0x00, buf[2]);
    EXPECT_EQ(0x00, buf[3]);
    buf.clear();

    serialize_length_into_buffer(128);
    ASSERT_EQ(2, buf.size());
    EXPECT_EQ(0x80, buf[0]);
    EXPECT_EQ(0x80, buf[1]);
}

TEST(LengthEncoding, length_coding_size)
{
    EXPECT_EQ(1, length_coding_size(0x3f));
    EXPECT_EQ(1, length_coding_size(0x20));
    EXPECT_EQ(1, length_coding_size(0x7f));
    EXPECT_EQ(1, length_coding_size(0x40));
    EXPECT_EQ(2, length_coding_size(0x3fff));
    EXPECT_EQ(2, length_coding_size(0x2000));
    EXPECT_EQ(3, length_coding_size(0x7fff));
    EXPECT_EQ(3, length_coding_size(0x4000));
    EXPECT_EQ(3, length_coding_size(0x1fffff));
    EXPECT_EQ(4, length_coding_size(0x3fffff));
}

TEST(LengthEncoding, WebValidator_length)
{
    ByteBuffer buf {{ 0x81, 0x03 }};
    vanetza::byte_buffer_source source(buf);
    boost::iostreams::stream_buffer<vanetza::byte_buffer_source> stream(source);
    InputArchive ia(stream);
    size_t length = deserialize_length(ia);
    EXPECT_EQ(259, length);
}
