#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/backend_null.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>

namespace vanetza
{
namespace security
{

EcdsaSignature BackendNull::sign_data(const ecdsa256::PrivateKey&, const ByteBuffer&)
{
    static const EcdsaSignature fake = fake_signature();
    return fake;
}

Signature BackendNull::sign_digest(const PrivateKey&, const ByteBuffer&)
{
    static const Signature empty {};
    return empty;
}

bool BackendNull::verify_data(const ecdsa256::PublicKey&, const ByteBuffer&, const EcdsaSignature&)
{
    // accept everything
    return true;
}

bool BackendNull::verify_digest(const PublicKey&, const ByteBuffer&, const Signature&)
{
    // accept everything
    return true;
}

boost::optional<Uncompressed> BackendNull::decompress_point(const EccPoint&)
{
    return boost::none;
}

EcdsaSignature BackendNull::fake_signature() const
{
    constexpr std::size_t size = 32;
    EcdsaSignature signature;
    X_Coordinate_Only coordinate;
    coordinate.x = random_byte_sequence(size, 0xdead);
    signature.R = coordinate;
    signature.s = random_byte_sequence(size, 0xbeef);

    return signature;
}

ByteBuffer BackendNull::calculate_hash(HashAlgorithm algo, const ByteBuffer&)
{
    ByteBuffer hash;
    switch (algo) {
        case HashAlgorithm::SHA256:
            hash.resize(32);
            break;
        case HashAlgorithm::SHA384:
            hash.resize(48);
            break;
        default:
            break;
    }
    return hash;
}

} // namespace security
} // namespace vanetza
