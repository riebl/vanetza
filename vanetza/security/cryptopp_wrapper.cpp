#include <vanetza/security/cryptopp_wrapper.hpp>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

namespace vanetza
{
namespace security
{
namespace cryptopp
{

CryptoPP::OID get_oid(KeyType key_type)
{
    if (key_type == KeyType::NistP256) {
        return CryptoPP::ASN1::secp256r1();
    } else if (key_type == KeyType::BrainpoolP256r1) {
        return CryptoPP::ASN1::brainpoolP256r1();
    } else if (key_type == KeyType::BrainpoolP384r1) {
        return CryptoPP::ASN1::brainpoolP384r1();
    } else {
        return CryptoPP::OID {};
    }
}

boost::optional<EcPublicKey> convert_public_key(const PublicKey& pub_key)
{
    EcPublicKey out;
    out.AccessGroupParameters().Initialize(get_oid(pub_key.type));
    auto& curve = out.GetGroupParameters().GetCurve();

    CryptoPP::ECP::Point point;
    ByteBuffer encoded_pub_key = encode_ec_point(pub_key);
    CryptoPP::StringStore store { encoded_pub_key.data(), encoded_pub_key.size() };
    if (!curve.DecodePoint(point, store, store.MaxRetrievable())) {
        return boost::none;
    }
    out.SetPublicElement(point);
    return out;
}

EcPrivateKey convert_private_key(const PrivateKey& priv_key)
{
    EcPrivateKey out;
    out.AccessGroupParameters().Initialize(get_oid(priv_key.type));
    out.SetPrivateExponent(CryptoPP::Integer(priv_key.key.data(), priv_key.key.size()));
    return out;
}

bool generate_random(std::uint8_t* buffer, std::size_t length)
{
    try {
        CryptoPP::OS_GenerateRandomBlock(false, buffer, length);
    } catch (const CryptoPP::OS_RNG_Err&) {
        return false;
    }
    return true;
}

CryptoPP::Integer digest_integer(const std::uint8_t* digest, std::size_t length, const CryptoPP::Integer& order)
{
    // ECDSA uses the leftmost bits of a digest longer than the curve order
    CryptoPP::Integer e { digest, length };
    const std::size_t digest_bits = 8 * length;
    const std::size_t order_bits = order.BitCount();
    if (digest_bits > order_bits) {
        e >>= digest_bits - order_bits;
    }
    return e;
}

} // namespace cryptopp
} // namespace security
} // namespace vanetza
