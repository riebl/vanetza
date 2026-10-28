#ifndef SHA_HPP_ENSVKDXU
#define SHA_HPP_ENSVKDXU

#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

using Sha256Digest = std::array<uint8_t, 32>;
using Sha384Digest = std::array<uint8_t, 48>;

Sha256Digest calculate_sha256_digest(const uint8_t* data, std::size_t len);
Sha384Digest calculate_sha384_digest(const uint8_t* data, std::size_t len);

struct Sha256Hash
{
    static constexpr std::size_t length = 32;
    std::array<std::uint8_t, length> octets;
};

bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs);
bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs);

struct Sha384Hash
{
    static constexpr std::size_t length = 48;
    std::array<std::uint8_t, length> octets;
};

bool operator==(const Sha384Hash& lhs, const Sha384Hash& rhs);
bool operator!=(const Sha384Hash& lhs, const Sha384Hash& rhs);

} // namespace security
} // namespace vanetza

#endif /* SHA_HPP_ENSVKDXU */

