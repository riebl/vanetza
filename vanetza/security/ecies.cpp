#include <vanetza/security/ecies.hpp>
#include <vanetza/security/hmac.hpp>
#include <vanetza/security/kdf2.hpp>
#include <algorithm>

namespace vanetza
{
namespace security
{

EncryptedSymmetricKey encrypt_key(
    const PublicKey& ephemeral_key, const byte_view_range& shared_secret, const Aes128Key& key, const Sha256Hash& info)
{
    static constexpr std::size_t ke_length = Aes128Key::length;
    static constexpr std::size_t km_length = HmacKey::length;

    // derive ke and km from shared secret
    const byte_view_range kdp { byte_view_iterator(info.octets.data()),
        byte_view_iterator(info.octets.data() + info.octets.size()) };
    const auto derived = kdf2<ke_length + km_length>(shared_secret, kdp);

    EncryptedSymmetricKey result;
    result.public_key = ephemeral_key;

    // encrypt symmetric key
    for (std::size_t i = 0; i < ke_length; ++i) {
        result.wrapped_key[i] = derived[i] ^ key.octets[i];
    }

    // generate authentication tag
    HmacKey km;
    std::copy_n(derived.begin() + ke_length, km_length, km.octets.begin());
    result.authentication_tag = create_hmac_tag(ByteBuffer(result.wrapped_key.begin(), result.wrapped_key.end()), km);

    return result;
}

} // namespace security
} // namespace vanetza
