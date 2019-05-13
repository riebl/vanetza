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

bool BackendNull::verify_data(const ecdsa256::PublicKey&, const ByteBuffer&, const EcdsaSignature&)
{
    // accept everything
    return true;
}

boost::optional<Uncompressed> BackendNull::decompress_point(const EccPoint& ecc_point)
{
    return boost::none;
}

EcdsaSignature BackendNull::fake_signature() const
{
    const std::size_t size = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    EcdsaSignature signature;
    X_Coordinate_Only coordinate;
    coordinate.x = random_byte_sequence(size, 0xdead);
    signature.R = coordinate;
    signature.s = random_byte_sequence(size, 0xbeef);

    return signature;
}

} // namespace security
} // namespace vanetza
