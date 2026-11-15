#include <vanetza/security/cryptopp_crypto_provider.hpp>
#include <vanetza/security/cryptopp_security_module.hpp>
#include <vanetza/security/cryptopp_wrapper.hpp>
#include <vanetza/security/ecies.hpp>
#include <cryptopp/misc.h>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{

namespace
{

// overwrites secret octets when leaving scope
class ScopedWipe
{
public:
    explicit ScopedWipe(ByteBuffer& data) : m_data(data) {}
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;
    ~ScopedWipe() { CryptoPP::SecureWipeBuffer(m_data.data(), m_data.size()); }

private:
    ByteBuffer& m_data;
};

// uniformly random integer of 0 < scalar < order, e.g. a private key or an ECDSA nonce
boost::optional<CryptoPP::Integer> random_scalar(const CryptoPP::Integer& order)
{
    ByteBuffer octets(order.ByteCount());
    ScopedWipe wipe(octets);
    CryptoPP::Integer scalar;
    do {
        if (!cryptopp::generate_random(octets.data(), octets.size())) {
            return boost::none;
        }
        scalar.Decode(octets.data(), octets.size());
    } while (scalar.IsZero() || scalar >= order);
    return scalar;
}

// private key of supported type and length, none for a scalar out of range
boost::optional<cryptopp::EcPrivateKey> build_private_key(const PrivateKey& priv_key)
{
    cryptopp::EcPrivateKey key = cryptopp::convert_private_key(priv_key);
    const CryptoPP::Integer& scalar = key.GetPrivateExponent();
    if (scalar.IsZero() || scalar >= key.GetGroupParameters().GetSubgroupOrder()) {
        return boost::none;
    }
    return key;
}

PublicKey compressed_public_key(KeyType type, const CryptoPP::ECP::Point& point)
{
    PublicKey key;
    key.type = type;
    key.compression = point.y.IsOdd() ? KeyCompression::Y1 : KeyCompression::Y0;
    key.x.resize(key_length(type));
    point.x.Encode(key.x.data(), key.x.size());
    return key;
}

} // namespace

CryptoppSecurityModule::CryptoppSecurityModule() : SoftwareSigningKeys(nullptr)
{
}

CryptoppSecurityModule::CryptoppSecurityModule(std::shared_ptr<CredentialStorage> storage) :
    SoftwareSigningKeys(storage)
{
}

expected<Aes128Key> CryptoppSecurityModule::generate_aes_key()
{
    Aes128Key key;
    if (!cryptopp::generate_random(key.octets.data(), key.octets.size())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<HmacKey> CryptoppSecurityModule::generate_hmac_key()
{
    HmacKey key;
    if (!cryptopp::generate_random(key.octets.data(), key.octets.size())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<EncryptedSymmetricKey> CryptoppSecurityModule::encrypt_key(
    const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info)
{
    if (key_length(recipient.type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    const boost::optional<cryptopp::EcPublicKey> recipient_key = cryptopp::convert_public_key(recipient);
    if (!recipient_key ||
        !recipient_key->GetGroupParameters().ValidateElement(1, recipient_key->GetPublicElement(), nullptr)) {
        return make_error_code(SecurityModuleError::InvalidPublicKey);
    }

    const auto& group = recipient_key->GetGroupParameters();
    const boost::optional<CryptoPP::Integer> ephemeral = random_scalar(group.GetSubgroupOrder());
    if (!ephemeral) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // ECDH shared secret is the x coordinate of the shared point
    ByteBuffer shared_secret(key_length(recipient.type));
    ScopedWipe wipe_shared_secret(shared_secret);
    group.ExponentiateElement(recipient_key->GetPublicElement(), *ephemeral).x.Encode(
        shared_secret.data(), shared_secret.size());

    // this software module derives keys and tag with Crypto++ like an HSM does internally
    CryptoppCryptoProvider crypto;
    return security::encrypt_key(crypto, compressed_public_key(recipient.type, group.ExponentiateBase(*ephemeral)),
        create_byte_view(shared_secret), key, info);
}

expected<KeyReference> CryptoppSecurityModule::create_signing_key(KeyType type)
{
    return create_key(type);
}

expected<KeyReference> CryptoppSecurityModule::find_signing_key(const PublicKey& key)
{
    return find_key(key);
}

expected<PublicKey> CryptoppSecurityModule::public_key(const KeyReference& reference)
{
    return public_key_of(reference);
}

expected<Signature> CryptoppSecurityModule::sign(const ByteBuffer& digest, const KeyReference& reference)
{
    return sign_with(digest, reference);
}

bool CryptoppSecurityModule::discard_key(const KeyReference& reference)
{
    return discard(reference);
}

expected<KeyReference> CryptoppSecurityModule::import_signing_key(const PrivateKey& key)
{
    return import_key(key);
}

expected<PrivateKey> CryptoppSecurityModule::generate_private_key(KeyType type)
{
    const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group { cryptopp::get_oid(type) };
    const boost::optional<CryptoPP::Integer> scalar = random_scalar(group.GetSubgroupOrder());
    if (!scalar) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    PrivateKey priv_key;
    priv_key.type = type;
    priv_key.key.resize(key_length(type));
    scalar->Encode(priv_key.key.data(), priv_key.key.size());
    return priv_key;
}

expected<PublicKey> CryptoppSecurityModule::derive_public_key(const PrivateKey& priv_key)
{
    const boost::optional<cryptopp::EcPrivateKey> key = build_private_key(priv_key);
    if (!key) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }
    return compressed_public_key(priv_key.type, key->GetGroupParameters().ExponentiateBase(key->GetPrivateExponent()));
}

expected<Signature> CryptoppSecurityModule::sign_digest(const ByteBuffer& digest, const PrivateKey& priv_key)
{
    const boost::optional<cryptopp::EcPrivateKey> key = build_private_key(priv_key);
    if (!key) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    const auto& group = key->GetGroupParameters();
    const CryptoPP::Integer e = cryptopp::digest_integer(digest.data(), digest.size(), group.GetSubgroupOrder());
    CryptoPP::Integer r;
    CryptoPP::Integer s;
    do {
        const boost::optional<CryptoPP::Integer> nonce = random_scalar(group.GetSubgroupOrder());
        if (!nonce) {
            return make_error_code(SecurityModuleError::ModuleFailure);
        }
        // Crypto++'s signer passes r = x(nonce * G) on, its ECDSA algorithm reduces r and calculates s
        r = group.ConvertElementToInteger(group.ExponentiateBase(*nonce));
        CryptoPP::DL_Algorithm_ECDSA<CryptoPP::ECP>().Sign(group, key->GetPrivateExponent(), *nonce, e, r, s);
    } while (r.IsZero() || s.IsZero());

    Signature signature;
    signature.type = priv_key.type;
    signature.r.resize(key_length(priv_key.type));
    signature.s.resize(key_length(priv_key.type));
    r.Encode(signature.r.data(), signature.r.size());
    s.Encode(signature.s.data(), signature.s.size());
    return signature;
}

} // namespace security
} // namespace vanetza
