#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace security
{

struct Aes128Key
{
    static constexpr std::size_t length = 16;
    std::array<std::uint8_t, length> octets;
};

bool operator==(const Aes128Key& lhs, const Aes128Key& rhs);
bool operator!=(const Aes128Key& lhs, const Aes128Key& rhs);

} // namespace security
} // namespace vanetza
