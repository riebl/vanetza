#include "ecies.hpp"
#include <vanetza/security/kdf2.hpp>
#include <cassert>

namespace vanetza
{
namespace pki
{

EncryptedSymmetricKey encrypt_key(SecurityModule& security, const SecurityModule::EciesContext& ecies,
    const ByteBuffer& key, const Sha256Hash& info)
{
    // ECIES encrypts AES-128 keys
    static constexpr std::size_t ke_length = 16;
    static constexpr std::size_t km_length = 32;
    assert(key.size() == ke_length);

    // derive ke and km from shared secret
    ByteBuffer kdp { info.octets.begin(), info.octets.end() };
    auto shared_secret_view = create_byte_view(ecies.shared_secret());
    auto kdp_view = create_byte_view(kdp);
    auto hashed_shared_secret = security::kdf2<ke_length + km_length>(shared_secret_view, kdp_view);
    assert(hashed_shared_secret.size() == ke_length + km_length);

    EncryptedSymmetricKey result;
    result.public_key = ecies.ephemeral_public_key();

    // encrypt symmetric key
    result.wrapped_key.resize(ke_length);
    std::uint8_t* ke = hashed_shared_secret.data();
    for (std::size_t i = 0; i < ke_length; ++i) {
        result.wrapped_key[i] = ke[i] ^ key[i];
    }

    // generate authentication tag
    ByteBuffer km { std::next(hashed_shared_secret.begin(), ke_length), hashed_shared_secret.end() };
    assert(km.size() == km_length);
    result.authentication_tag = security.calculate_hmac_sha256(km, result.wrapped_key);

    return result;
}

} // namespace pki
} // namespace vanetza
