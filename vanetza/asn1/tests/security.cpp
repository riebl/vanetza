#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(Time64.h)
#include VANETZA_ASN1_SECURITY_HEADER(Uint64.h)
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

#ifdef VANETZA_WITH_PQC
#include VANETZA_ASN1_SECURITY_HEADER(PublicVerificationKey.h)
#include VANETZA_ASN1_SECURITY_HEADER(Signature.h)
#include VANETZA_ASN1_SECURITY_HEADER(ToBeSignedCertificate.h)
#endif

using namespace vanetza::asn1;

TEST(SecurityAsn1, Time64)
{
    asn1c_wrapper<Vanetza_Security_Time64_t> time { asn_DEF_Vanetza_Security_Time64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*time, std::numeric_limits<std::uint64_t>::max()));

    std::uint64_t tmp = 0;
    asn_INTEGER2umax(&*time, &tmp);
    EXPECT_EQ(tmp, std::numeric_limits<std::uint64_t>::max());

    time.encode();
    EXPECT_EQ(8, time.size());
}

TEST(SecuriyAsn1, Uint64)
{
    asn1c_wrapper<Vanetza_Security_Uint64_t> uint { asn_DEF_Vanetza_Security_Uint64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*uint, std::numeric_limits<std::uint64_t>::max()));

    std::uint64_t tmp = 0;
    asn_INTEGER2umax(&*uint, &tmp);
    EXPECT_EQ(tmp, std::numeric_limits<std::uint64_t>::max());

    uint.encode();
    EXPECT_EQ(8, uint.size());
}

TEST(SecurityAsn1, Uint64_roundtrip_max_value)
{
    asn1c_wrapper<Vanetza_Security_Uint64_t> tx { asn_DEF_Vanetza_Security_Uint64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*tx, std::numeric_limits<std::uint64_t>::max()));
    const vanetza::ByteBuffer buffer = tx.encode();
    EXPECT_EQ(8, buffer.size());
    EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(),
                [](std::uint8_t c) { return c == 0xff; }));

    asn1c_wrapper<Vanetza_Security_Uint64_t> rx { asn_DEF_Vanetza_Security_Uint64 };
    EXPECT_TRUE(rx.decode(buffer));
    std::uint64_t value = 0;
    EXPECT_EQ(0, asn_INTEGER2umax(&*rx, &value));
    EXPECT_EQ(value, std::numeric_limits<std::uint64_t>::max());
}

#ifdef VANETZA_WITH_PQC
TEST(SecurityAsn1, HybridPqcExtensions)
{
    std::array<char, 897> public_key_bytes {{}};
    asn1c_oer_wrapper<Vanetza_Security_PublicVerificationKey_t> public_key {
        asn_DEF_Vanetza_Security_PublicVerificationKey
    };
    public_key->present = Vanetza_Security_PublicVerificationKey_PR_fnDsa512;
    ASSERT_EQ(0, OCTET_STRING_fromBuf(
            &public_key->choice.fnDsa512, public_key_bytes.data(), public_key_bytes.size()));
    ASSERT_TRUE(public_key.validate());

    const auto encoded_public_key = public_key.encode();
    asn1c_oer_wrapper<Vanetza_Security_PublicVerificationKey_t> decoded_public_key {
        asn_DEF_Vanetza_Security_PublicVerificationKey
    };
    ASSERT_TRUE(decoded_public_key.decode(encoded_public_key));
    EXPECT_EQ(Vanetza_Security_PublicVerificationKey_PR_fnDsa512, decoded_public_key->present);
    EXPECT_EQ(public_key_bytes.size(), decoded_public_key->choice.fnDsa512.size);

    std::array<char, 666> signature_bytes {{}};
    asn1c_oer_wrapper<Vanetza_Security_Signature_t> signature {
        asn_DEF_Vanetza_Security_Signature
    };
    signature->present = Vanetza_Security_Signature_PR_fnDsa512Signature;
    ASSERT_EQ(0, OCTET_STRING_fromBuf(
            &signature->choice.fnDsa512Signature, signature_bytes.data(), signature_bytes.size()));
    ASSERT_TRUE(signature.validate());

    const auto encoded_signature = signature.encode();
    asn1c_oer_wrapper<Vanetza_Security_Signature_t> decoded_signature {
        asn_DEF_Vanetza_Security_Signature
    };
    ASSERT_TRUE(decoded_signature.decode(encoded_signature));
    EXPECT_EQ(Vanetza_Security_Signature_PR_fnDsa512Signature, decoded_signature->present);
    EXPECT_EQ(signature_bytes.size(), decoded_signature->choice.fnDsa512Signature.size);

    Vanetza_Security_ToBeSignedCertificate_t certificate {{}};
    EXPECT_EQ(nullptr, certificate.altVerificationKey);
    EXPECT_EQ(nullptr, certificate.altSignatureValue);
}
#endif
