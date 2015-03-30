#ifndef BASIC_ELEMENTS_HPP_RALCTYHI
#define BASIC_ELEMENTS_HPP_RALCTYHI

#include <vanetza/common/byte_order.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{
using Time64 = uint64_t;
using Time32 = uint32_t;

using HashedId8 = std::array<uint8_t, 8>;
using HashedId3 = std::array<uint8_t, 3>;

HashedId3 truncate(const HashedId8&);

struct Time64WithStandardDeviation
{
    Time64 time64;
    uint8_t log_std_dev;
};

} // namespace security
} // namespace vanetza

#endif /* BASIC_ELEMENTS_HPP_RALCTYHI */

