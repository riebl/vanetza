#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cryptopp/oids.h>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <functional>

namespace vanetza
{
namespace security
{

namespace {

CryptoPP::ECP::Point make_ecp_point(const PublicKey& public_key)
{
    CryptoPP::Integer x { public_key.x.data(), public_key.x.size() };
    CryptoPP::Integer y { public_key.y.data(), public_key.y.size() };
    return CryptoPP::ECP::Point { std::move(x), std::move(y) };
}

} // namespace

using std::placeholders::_1;

BackendCryptoPP::BackendCryptoPP() :
    m_private_cache(std::bind(&BackendCryptoPP::internal_private_key, this, _1), 8),
    m_public_cache(std::bind(&BackendCryptoPP::internal_public_key, this, _1), 2048)
{
}

EcdsaSignature BackendCryptoPP::sign_data(const ecdsa256::PrivateKey& generic_key, const ByteBuffer& data)
{
    return sign_data(m_private_cache[generic_key], data);
}

EcdsaSignature BackendCryptoPP::sign_data(const Ecdsa256::PrivateKey& private_key, const ByteBuffer& data)
{
    // calculate signature
    Ecdsa256::Signer signer(private_key);
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

bool BackendCryptoPP::verify_data(const ecdsa256::PublicKey& generic_key, const ByteBuffer& msg, const EcdsaSignature& sig)
{
    const ByteBuffer sigbuf = extract_signature_buffer(sig);
    return verify_data(m_public_cache[generic_key], msg, sigbuf);
}

bool BackendCryptoPP::verify_data(const PublicKey& public_key, const ByteBuffer& msg, const Signature& sig)
{
    if (public_key.type != sig.type) {
        return false;
    }

    Ecdsa256::PublicKey pub;
    if (public_key.type == KeyType::NistP256) {
        pub.Initialize(CryptoPP::ASN1::secp256r1(), make_ecp_point(public_key));
    } else if (sig.type == KeyType::BrainpoolP256r1) {
        pub.Initialize(CryptoPP::ASN1::brainpoolP256r1(), make_ecp_point(public_key));
    } else if (sig.type == KeyType::BrainpoolP384r1) {
        pub.Initialize(CryptoPP::ASN1::brainpoolP384r1(), make_ecp_point(public_key));
    }

    if (!pub.Validate(m_prng, 3)) {
        return false;
    }

    switch (sig.type) {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1: {
            Ecdsa256::Verifier verifier(pub);
            ByteBuffer sigbuf = extract_signature_buffer(sig);
            return verifier.VerifyMessage(msg.data(), msg.size(), sigbuf.data(), sigbuf.size());
        }
        case KeyType::BrainpoolP384r1: {
            Ecdsa384::Verifier verifier(pub);
            ByteBuffer sigbuf = extract_signature_buffer(sig);
            return verifier.VerifyMessage(msg.data(), msg.size(), sigbuf.data(), sigbuf.size());
        }
        default:
            return false;
    }
}

bool BackendCryptoPP::verify_data(const Ecdsa256::PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Ecdsa256::Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}


boost::optional<Uncompressed> BackendCryptoPP::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            decompress(p.x, 0x02);
            return true;
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            decompress(p.x, 0x03);
            return true;
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        void decompress(const ByteBuffer& x, ByteBuffer::value_type type)
        {
            ByteBuffer compact;
            compact.reserve(x.size() + 1);
            compact.push_back(type);
            std::copy(x.begin(), x.end(), std::back_inserter(compact));

            BackendCryptoPP::Point point;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group(CryptoPP::ASN1::secp256r1());
            group.GetCurve().DecodePoint(point, compact.data(), compact.size());

            result.x = x;
            result.y.resize(result.x.size());
            point.y.Encode(result.y.data(), result.y.size());
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

ByteBuffer BackendCryptoPP::calculate_hash(KeyType key, const ByteBuffer& buffer)
{
    ByteBuffer hash;
    switch (key) {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1: {
            CryptoPP::SHA256 algo;
            hash.resize(algo.DigestSize());
            algo.CalculateDigest(hash.data(), buffer.data(), buffer.size());
            break;
        }
        case KeyType::BrainpoolP384r1: {
            CryptoPP::SHA384 algo;
            hash.resize(algo.DigestSize());
            algo.CalculateDigest(hash.data(), buffer.data(), buffer.size());
            break;
        }
        default:
            break;
    }

    return hash;
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

BackendCryptoPP::Ecdsa256::PrivateKey BackendCryptoPP::generate_private_key()
{
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    Ecdsa256::PrivateKey private_key;
    private_key.Initialize(m_prng, oid);
    assert(private_key.Validate(m_prng, 3));
    return private_key;
}

BackendCryptoPP::Ecdsa256::PublicKey BackendCryptoPP::generate_public_key(const Ecdsa256::PrivateKey& private_key)
{
    Ecdsa256::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    assert(public_key.Validate(m_prng, 3));
    return public_key;
}

BackendCryptoPP::Ecdsa256::PublicKey BackendCryptoPP::internal_public_key(const ecdsa256::PublicKey& generic)
{
    CryptoPP::Integer x { generic.x.data(), generic.x.size() };
    CryptoPP::Integer y { generic.y.data(), generic.y.size() };
    CryptoPP::ECP::Point q { x, y };

    Ecdsa256::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);
    assert(pub.Validate(m_prng, 3));
    return pub;
}

BackendCryptoPP::Ecdsa256::PrivateKey BackendCryptoPP::internal_private_key(const ecdsa256::PrivateKey& generic)
{
    Ecdsa256::PrivateKey key;
    CryptoPP::Integer integer { generic.key.data(), generic.key.size() };
    key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    return key;
}

} // namespace security
} // namespace vanetza
