#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cryptopp/filters.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cassert>

namespace vanetza
{
namespace security
{

EcdsaSignature BackendCryptoPP::sign_data(const PrivateKey& private_key, const ByteBuffer& data)
{
    CryptoPP::AutoSeededRandomPool prng;

    // calculate signature
    Signer signer(private_key);
    ByteBuffer signature(signer.MaxSignatureLength(), 0x00);
    auto signature_length = signer.SignMessage(prng, data.data(), data.size(), signature.data());
    signature.resize(signature_length);

    auto signature_delimiter = signature.begin();
    std::advance(signature_delimiter, 32);

    EcdsaSignature ecdsa_signature;
    // set R
    X_Coordinate_Only coordinate;
    coordinate.x = ByteBuffer(signature.begin(), signature_delimiter);
    ecdsa_signature.R = std::move(coordinate);
    // set s
    ByteBuffer trailer_field_buffer(signature_delimiter, signature.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);

    return ecdsa_signature;
}

bool BackendCryptoPP::verify_data(const PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}

BackendCryptoPP::KeyPair BackendCryptoPP::generate_key_pair()
{
    KeyPair key_pair;
    // generate private key
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    CryptoPP::AutoSeededRandomPool prng;
    key_pair.private_key.Initialize(prng, oid);
    assert(key_pair.private_key.Validate(prng, 3));

    // generate public key
    key_pair.private_key.MakePublicKey(key_pair.public_key);
    assert(key_pair.public_key.Validate(prng, 3));

    return key_pair;
}

BackendCryptoPP::PublicKey BackendCryptoPP::public_key(const Uncompressed& unc)
{
    CryptoPP::Integer x { unc.x.data(), unc.x.size() };
    CryptoPP::Integer y { unc.y.data(), unc.y.size() };
    CryptoPP::ECP::Point q { x, y };

    BackendCryptoPP::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);

    CryptoPP::AutoSeededRandomPool prng;
    assert(pub.Validate(prng, 3));

    return pub;
}

} // namespace security
} // namespace vanetza
