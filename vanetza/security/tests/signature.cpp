#include <gtest/gtest.h>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

TEST(Signature, serialize) {
    Signature sig = setSignature_Ecdsa_Signature();

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, sig);

    Signature deserializedSig;
    InputArchive ia(stream);
    deserialize(ia, deserializedSig);

    testSignature_Ecdsa_Signature(sig, deserializedSig);
}
