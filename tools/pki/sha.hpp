#pragma once

#include <vanetza/security/hash_algorithm.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace pki
{

using security::HashAlgorithm;

struct Sha256Hash
{
    static constexpr std::size_t length = 32;
    std::array<std::uint8_t, length> octets;
};

struct Sha384Hash
{
    static constexpr std::size_t length = 48;
    std::array<std::uint8_t, length> octets;
};

} // namespace pki
} // namespace vanetza
