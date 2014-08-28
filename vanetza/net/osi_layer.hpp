#ifndef OSI_LAYER_HPP_C4VTEZJP
#define OSI_LAYER_HPP_C4VTEZJP

#include <array>
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

constexpr OsiLayer min_osi_layer() { return OsiLayer::Physical; }
constexpr OsiLayer max_osi_layer() { return OsiLayer::Application; }

constexpr std::array<OsiLayer, 7> osi_layers {{
            OsiLayer::Physical,
            OsiLayer::Link,
            OsiLayer::Network,
            OsiLayer::Transport,
            OsiLayer::Session,
            OsiLayer::Presentation,
            OsiLayer::Application
}};

constexpr std::size_t num_osi_layers(OsiLayer from, OsiLayer to)
{
    typedef typename std::underlying_type<OsiLayer>::type num_type;
    return static_cast<num_type>(from) <= static_cast<num_type>(to) ?
        static_cast<num_type>(to) - static_cast<num_type>(from) + 1 :
        0;
}

template<OsiLayer FROM, OsiLayer TO>
std::array<OsiLayer, num_osi_layers(FROM, TO)> osi_layer_range()
{
    static_assert(FROM <= TO, "FROM layer is above TO layer");
    typedef typename std::underlying_type<OsiLayer>::type num_type;

    num_type num = static_cast<num_type>(FROM);
    std::array<OsiLayer, num_osi_layers(FROM, TO)> layers;
    for (auto& layer : layers) {
        layer = static_cast<OsiLayer>(num++);
    }
    return layers;
}

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

