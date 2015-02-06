#include <gtest/gtest.h>
#include <vanetza/security/length_coding.hpp>

using vanetza::ByteBuffer;
using namespace vanetza::security;

TEST(LengthEncoding, count_leading_ones) {
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

TEST(LengthEncoding, encode_length) {
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

TEST(LengthEncoding, decode_length_empty_buffer) {
    ByteBuffer buffer;
    EXPECT_FALSE(!!decode_length(buffer));
}

TEST(LengthEncoding, decode_length_zero_size) {
    ByteBuffer buffer { 0x00 };
    auto decoded_tuple = decode_length(buffer);
    ASSERT_TRUE(!!decoded_tuple);
    EXPECT_EQ(buffer.end(), std::get<0>(*decoded_tuple));
    EXPECT_EQ(0, std::get<1>(*decoded_tuple));
}

TEST(LengthEncoding, decode_length_prefix_too_long) {
    ByteBuffer buffer { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xba, 0xbe };
    EXPECT_FALSE(!!decode_length(buffer));
}

TEST(LengthEncoding, decode_length_buffer_too_short) {
    ByteBuffer buffer { 0x02, 0xde };
    auto decoded_tuple = decode_length(buffer);
    ASSERT_TRUE(!!decoded_tuple);
    EXPECT_EQ(buffer.begin() += 1, std::get<0>(*decoded_tuple));
    EXPECT_EQ(2, std::get<1>(*decoded_tuple));
}

TEST(LengthEncoding, decode_length_good) {
    ByteBuffer buffer { 0xe0, 0x00, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78, 0x9a,
            0xbc, 0xde };
    auto decoded_tuple = decode_length(buffer);
    ASSERT_TRUE(!!decoded_tuple);
    EXPECT_EQ(buffer.begin() += 4, std::get<0>(*decoded_tuple));
    EXPECT_EQ(4, std::get<1>(*decoded_tuple));
}

TEST(LengthEncoding, decode_length_range_empty_buffer) {
    ByteBuffer buffer;
    EXPECT_EQ(boost::make_iterator_range(buffer), decode_length_range(buffer));
}

TEST(LengthEncoding, decode_length_range_zero_size) {
    ByteBuffer buffer { 0x00 };
    EXPECT_EQ(boost::make_iterator_range(buffer.end(), buffer.end()),
            decode_length_range(buffer));
}

TEST(LengthEncoding, decode_length_range_prefix_too_long) {
    ByteBuffer buffer { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xba, 0xbe };
    EXPECT_EQ(boost::make_iterator_range(buffer), decode_length_range(buffer));
}

TEST(LengthEncoding, decode_length_range_buffer_too_short) {
    ByteBuffer buffer { 0x02, 0xde };
    EXPECT_EQ(boost::make_iterator_range(buffer), decode_length_range(buffer));
}

TEST(LengthEncoding, decode_length_range_good) {
    ByteBuffer buffer { 0xe0, 0x01, 0x00, 0x00 };
    std::fill_n(std::back_inserter(buffer), 0x010000, 0x11);
    EXPECT_EQ(boost::make_iterator_range(buffer, 4, 0),
            decode_length_range(buffer));

    std::fill_n(std::back_inserter(buffer), 19, 0x22);
    EXPECT_EQ(boost::make_iterator_range(buffer, 4, -19),
            decode_length_range(buffer));

    auto result = decode_length_range(buffer);
    EXPECT_TRUE(
            std::all_of(result.begin(), result.end(),
                    [](uint8_t x) {return x == 0x11;}));
}

void serialize_length(size_t size) {
    std::stringstream stream;
    OutputArchive oa2(stream);
    serialize_length(oa2, size);

    InputArchive ia(stream);
    size_t deSize = deserialize_length(ia);

    EXPECT_EQ(size, deSize);
}

TEST(LengthEncoding, serialize_length) {
    serialize_length(0x200000);
    serialize_length(128);
}
