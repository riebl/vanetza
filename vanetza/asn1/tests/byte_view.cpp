#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <gtest/gtest.h>

using namespace vanetza;

TEST(Asn1ByteView, assign_replaces_content)
{
    const ByteBuffer previous { 0x01, 0x02, 0x03 };
    const ByteBuffer bytes { 0x04, 0x05 };
    OCTET_STRING_t octets {};
    asn1::assign(octets, create_byte_view(previous));
    asn1::assign(octets, create_byte_view(bytes));
    EXPECT_EQ(create_byte_view(bytes), asn1::create_byte_view(octets));
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &octets);
}
