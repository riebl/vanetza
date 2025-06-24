#pragma once
#include <vanetza/access/access_category.hpp>
#include <cstdint>

namespace vanetza
{
namespace access
{

/**
 * \brief map access category to PPPP for C-V2X
 *
 * Mapping is according to EN 303 613 V1.1.1 Table B.7
 *
 * \param ac access category from 802.11
 * \return matching PPPP value
 */
constexpr std::uint8_t pppp_from_ac(AccessCategory ac)
{
    switch (ac) {
        case AccessCategory::VO:
            return 2;
        case AccessCategory::VI:
            return 4;
        case AccessCategory::BE:
            return 5;
        case AccessCategory::BK:
        default:
            return 7;
    }
}

} // namespace access
} // namespace vanetza

