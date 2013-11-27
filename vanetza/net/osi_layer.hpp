#ifndef OSI_LAYER_HPP_C4VTEZJP
#define OSI_LAYER_HPP_C4VTEZJP

#include <cstdint>

namespace vanetza
{

enum class OsiLayer : uint8_t
{
    Physical = 1,
    Link = 2,
    Network = 3,
    Transport = 4,
    Session = 5,
    Presentation = 6,
    Application = 7
};

constexpr bool operator<(OsiLayer lhs, OsiLayer rhs)
{
    return static_cast<uint8_t>(lhs) < static_cast<uint8_t>(rhs);
}

constexpr bool operator==(OsiLayer lhs, OsiLayer rhs)
{
    return static_cast<uint8_t>(lhs) == static_cast<uint8_t>(rhs);
}

constexpr bool operator!=(OsiLayer lhs, OsiLayer rhs) { return !(lhs == rhs); }
constexpr bool operator>=(OsiLayer lhs, OsiLayer rhs) { return !(lhs < rhs); }
constexpr bool operator<=(OsiLayer lhs, OsiLayer rhs) { return (lhs < rhs || lhs == rhs); }
constexpr bool operator>(OsiLayer lhs, OsiLayer rhs) { return  !(lhs <= rhs); }

} // namespace vanetza

#endif /* OSI_LAYER_HPP_C4VTEZJP */

