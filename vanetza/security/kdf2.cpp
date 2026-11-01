#include <vanetza/security/kdf2.hpp>
#include <vanetza/security/sha.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace security
{
namespace detail
{

void kdf2(const byte_view_range& secret, const byte_view_range& kdp, std::uint8_t* out, std::size_t length)
{
    static constexpr std::size_t counter_length = 4;

    ByteBuffer concat;
    concat.reserve(secret.size() + counter_length + kdp.size());
    // start concatenation with shared secret
    concat.insert(concat.end(), secret.begin(), secret.end());
    // placeholder for 4-byte counter, set by each iteration
    const std::size_t counter_offset = concat.size();
    concat.insert(concat.end(), counter_length, 0x00);
    // finalize with key derivation parameter (P1)
    concat.insert(concat.end(), kdp.begin(), kdp.end());

    std::size_t derived = 0;

    // each iteration adds 32 bytes (SHA-256 hash)
    const std::uint32_t iterations = length / Sha256Hash::length + (length % Sha256Hash::length ? 1 : 0);

    // initialize counter with 1: see IEEE 1363.2a-2004 KDF2
    for (std::uint32_t counter = 1; counter <= iterations; ++counter) {
        // set 4-byte counter in big-endian order
        concat[counter_offset] = static_cast<std::uint8_t>(counter >> 24);
        concat[counter_offset + 1] = static_cast<std::uint8_t>(counter >> 16);
        concat[counter_offset + 2] = static_cast<std::uint8_t>(counter >> 8);
        concat[counter_offset + 3] = static_cast<std::uint8_t>(counter);

        const Sha256Digest hash = calculate_sha256_digest(concat.data(), concat.size());

        // left most bytes are the derived key
        const std::size_t count = std::min(length - derived, hash.size());
        std::copy_n(hash.begin(), count, out + derived);
        derived += count;
    }

    assert(derived == length);
}

} // namespace detail

ByteBuffer kdf2(const byte_view_range& secret, const byte_view_range& kdp, std::size_t length)
{
    ByteBuffer derived(length);
    detail::kdf2(secret, kdp, derived.data(), derived.size());
    return derived;
}

} // namespace security
} // namespace vanetza
