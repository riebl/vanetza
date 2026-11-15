#include <vanetza/security/cryptopp_wrapper.hpp>
#include <cryptopp/oids.h>

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

} // namespace cryptopp
} // namespace security
} // namespace vanetza
