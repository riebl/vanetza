#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/VanetzaTest.h>
#include <vanetza/asn1/support/asn_bit_data.h>
#include <vanetza/asn1/support/asn_internal.h>

// OER decoding of a SEQUENCE without optional members and extensions creates a zero-bit
// preamble from the input pointer, which is null for an empty buffer (memcpy from null).

TEST(BitData, new_contiguous_accepts_null_source_with_zero_bits)
{
    asn_bit_data_t* pd = asn_bit_data_new_contiguous(nullptr, 0);
    ASSERT_NE(nullptr, pd);
    EXPECT_EQ(0, pd->nbits);
    EXPECT_EQ(0, pd->nboff);
    EXPECT_NE(nullptr, pd->buffer);
    EXPECT_EQ(0, pd->buffer[0]);
    FREEMEM(pd);
}

TEST(BitData, oer_decode_of_empty_buffer)
{
    vanetza::asn1::asn1c_oer_wrapper<VanetzaTest_t> wrapper { asn_DEF_VanetzaTest };
    const vanetza::ByteBuffer empty;
    EXPECT_FALSE(wrapper.decode(empty));
}
