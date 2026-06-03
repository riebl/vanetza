#include "ecies.hpp"
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace pki
{

ByteBuffer calculate_kdf2(SecurityModule& security, const ByteBuffer& shared_secret, const ByteBuffer& kdp,
    std::size_t dl)
{
    Sha256Function fn = [&security](const ByteBuffer& buffer) {
        return security.calculate_sha256_hash(buffer.data(), buffer.size());
    };
    return calculate_kdf2(fn, shared_secret, kdp, dl);
}

ByteBuffer calculate_kdf2(Sha256Function hash_fn, const ByteBuffer& shared_secret, const ByteBuffer& kdp,
    std::size_t dl)
{
    ByteBuffer derived;
    ByteBuffer concat;

    // each iteration adds 32 bytes (SHA-256 hash)
    const std::uint32_t iterations = dl / Sha256Hash::length + (dl % Sha256Hash::length ? 1 : 0);

    // initialize counter with 1: see IEEE 1363.2a-2004 KDF2
    for (std::uint32_t counter = 1; counter <= iterations; ++counter) {
        // start concatenation with shared secret
        concat = shared_secret;
        // append 4-byte counter in big-endian order
        concat.insert(concat.end(), {
            static_cast<std::uint8_t>(counter >> 24),
            static_cast<std::uint8_t>(counter >> 16),
            static_cast<std::uint8_t>(counter >> 8),
            static_cast<std::uint8_t>(counter)
        });
        // finalize with key derivation parameter (P1)
        concat.insert(concat.end(), kdp.begin(), kdp.end());

        Sha256Hash hash = hash_fn(concat);
        std::copy(hash.octets.begin(), hash.octets.end(), std::back_inserter(derived));
    }

    // left most bytes are the derived key
    assert(derived.size() >= dl);
    derived.resize(dl);
    return derived;
}

EncryptedSymmetricKey encrypt_key(SecurityModule& security, const SecurityModule::EciesContext& ecies,
    const ByteBuffer& key, const Sha256Hash& info)
{
    const std::size_t ke_length = key.size();
    static constexpr std::size_t km_length = 32;

    // derive ke and km from shared secret
    ByteBuffer kdp { info.octets.begin(), info.octets.end() };
    auto hashed_shared_secret = calculate_kdf2(security, ecies.shared_secret(), kdp, ke_length + km_length);
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
