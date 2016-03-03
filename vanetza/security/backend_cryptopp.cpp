#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cryptopp/oids.h>
#include <cassert>

namespace vanetza
{
namespace security
{

EcdsaSignature BackendCryptoPP::sign_data(const ecdsa256::PrivateKey& generic_key, const ByteBuffer& data)
{
    PrivateKey key;
    CryptoPP::Integer integer { generic_key.key.data(), generic_key.key.size() };
    key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    return sign_data(key, data);
}

EcdsaSignature BackendCryptoPP::sign_data(const PrivateKey& private_key, const ByteBuffer& data)
{
    // calculate signature
    Signer signer(private_key);
    ByteBuffer signature(signer.MaxSignatureLength(), 0x00);
    auto signature_length = signer.SignMessage(m_prng, data.data(), data.size(), signature.data());
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

bool BackendCryptoPP::verify_data(const ecdsa256::PublicKey& generic_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    return verify_data(internal_public_key(generic_key), msg, sig);
}

bool BackendCryptoPP::verify_data(const PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}

ecdsa256::KeyPair BackendCryptoPP::generate_key_pair()
{
    ecdsa256::KeyPair kp;
    auto private_key = generate_private_key();
    auto& private_exponent = private_key.GetPrivateExponent();
    assert(kp.private_key.key.size() >= private_exponent.ByteCount());
    private_exponent.Encode(kp.private_key.key.data(), kp.private_key.key.size());

    auto public_key = generate_public_key(private_key);
    auto& public_element = public_key.GetPublicElement();
    assert(kp.public_key.x.size() >= public_element.x.ByteCount());
    assert(kp.public_key.y.size() >= public_element.y.ByteCount());
    public_element.x.Encode(kp.public_key.x.data(), kp.public_key.x.size());
    public_element.y.Encode(kp.public_key.y.data(), kp.public_key.y.size());
    return kp;
}

BackendCryptoPP::PrivateKey BackendCryptoPP::generate_private_key()
{
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    PrivateKey private_key;
    private_key.Initialize(m_prng, oid);
    assert(private_key.Validate(m_prng, 3));
    return private_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::generate_public_key(const PrivateKey& private_key)
{
    PublicKey public_key;
    private_key.MakePublicKey(public_key);
    assert(public_key.Validate(m_prng, 3));
    return public_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::internal_public_key(const ecdsa256::PublicKey& generic)
{
    CryptoPP::Integer x { generic.x.data(), generic.x.size() };
    CryptoPP::Integer y { generic.y.data(), generic.y.size() };
    CryptoPP::ECP::Point q { x, y };

    BackendCryptoPP::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);
    assert(pub.Validate(m_prng, 3));
    return pub;
}

} // namespace security
} // namespace vanetza
