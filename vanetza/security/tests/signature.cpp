#include <gtest/gtest.h>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>
#include <vanetza/security/tests/web_validator.hpp>

TEST(Signature, serialize)
{
    Signature sig = setSignature_Ecdsa_Signature();

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, sig);

    Signature deserializedSig;
    InputArchive ia(stream);
    deserialize(ia, deserializedSig);

    testSignature_Ecdsa_Signature(sig, deserializedSig);
}

TEST(Signature, WebValidator_Size)
{
    Signature sig;
    EcdsaSignature eSig;
    X_Coordinate_Only x;

    byteBuffer_from_string(x.x, "8DA1F3F9F35E04C3DE77D7438988A8D57EBE44DAA021A4269E297C177C9CFE45");
    eSig.R = x;

    byteBuffer_from_string(eSig.s,
        "8E128EC290785D6631961625020943B6D87DAA54919A98F7865709929A7C6E48");
    sig = eSig;

    EXPECT_EQ(66, get_size(sig));
}
