#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_view.hpp>
#include <array>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace detail
{

void kdf2(const byte_view_range& secret, const byte_view_range& kdp, std::uint8_t* out, std::size_t length);

} // namespace detail

/**
 * Derive key by KDF2 of IEEE 1363a with SHA-256
 * \param secret shared secret
 * \param kdp key derivation parameter
 * \param length length of derived key in octets
 * \return derived key
 */
ByteBuffer kdf2(const byte_view_range& secret, const byte_view_range& kdp, std::size_t length);

/**
 * Derive key by KDF2 of IEEE 1363a with SHA-256
 * \tparam N length of derived key in octets
 * \param secret shared secret
 * \param kdp key derivation parameter
 * \return derived key
 */
template<std::size_t N> std::array<std::uint8_t, N> kdf2(const byte_view_range& secret, const byte_view_range& kdp)
{
    std::array<std::uint8_t, N> derived;
    detail::kdf2(secret, kdp, derived.data(), derived.size());
    return derived;
}

} // namespace security
} // namespace vanetza
